package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type records struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
}

func (r records) any() bool { return len(r.A)+len(r.AAAA)+len(r.CNAME) > 0 }

func (r *records) merge(other records) {
	r.A = sortedUnique(append(r.A, other.A...))
	r.AAAA = sortedUnique(append(r.AAAA, other.AAAA...))
	r.CNAME = sortedUnique(append(r.CNAME, other.CNAME...))
}

func sortedUnique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func (r records) equal(other records) bool {
	return slices.Equal(r.A, other.A) && slices.Equal(r.AAAA, other.AAAA) && slices.Equal(r.CNAME, other.CNAME)
}

func (r records) confirmedBy(other records) bool {
	return len(r.A) > 0 && len(other.A) > 0 || len(r.AAAA) > 0 && len(other.AAAA) > 0 || len(r.CNAME) > 0 && len(other.CNAME) > 0
}

type result struct {
	Input                string  `json:"input"`
	Domain               string  `json:"domain,omitempty"`
	Status               string  `json:"status"`
	Reason               string  `json:"reason"`
	Detail               string  `json:"detail,omitempty"`
	Resolver             string  `json:"resolver,omitempty"`
	ConfirmationResolver string  `json:"confirmation_resolver,omitempty"`
	Records              records `json:"records"`
	Confirmed            bool    `json:"confirmed"`
	WildcardChecked      bool    `json:"wildcard_checked"`
}

type domainChecker struct {
	o                     options
	primary, confirmation *resolverPool
	probeName             func(string) (string, error)
}

func newDomainChecker(o options, servers, confirmation []string) *domainChecker {
	transport := newDNSTransport(o)
	primary := newResolverPool(servers, o, transport)
	confirm := primary
	if len(confirmation) > 0 {
		confirm = newResolverPool(confirmation, o, transport)
	}
	return &domainChecker{o: o, primary: primary, confirmation: confirm, probeName: wildcardProbeName}
}

func wildcardProbeName(parent string) (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "dnscheck-" + hex.EncodeToString(random[:]) + "." + parent, nil
}

// answerRecords follows only owner names reachable from the queried name.
// Unrelated records in a reply must not turn an empty answer into a match.
func answerRecords(name string, msg *dns.Msg) (records, error) {
	var out records
	if msg == nil || len(msg.Question) != 1 {
		return out, errors.New("DNS answer has no unique question")
	}
	qtype := msg.Question[0].Qtype
	byOwner := make(map[string][]dns.RR)
	for _, rr := range msg.Answer {
		if rr.Header().Class == dns.ClassINET {
			owner := dns.CanonicalName(rr.Header().Name)
			byOwner[owner] = append(byOwner[owner], rr)
		}
	}
	owner := dns.CanonicalName(name)
	seen := make(map[string]bool)
	for range 16 {
		if seen[owner] {
			return records{}, errors.New("CNAME loop in DNS answer")
		}
		seen[owner] = true
		target := ""
		hasAddress := false
		var atOwner records
		for _, rr := range byOwner[owner] {
			switch value := rr.(type) {
			case *dns.A:
				hasAddress = true
				if qtype == dns.TypeA {
					atOwner.A = append(atOwner.A, value.A.String())
				}
			case *dns.AAAA:
				hasAddress = true
				if qtype == dns.TypeAAAA {
					atOwner.AAAA = append(atOwner.AAAA, value.AAAA.String())
				}
			case *dns.CNAME:
				next := dns.CanonicalName(value.Target)
				if next == "." {
					return records{}, errors.New("CNAME target is the DNS root")
				}
				if target != "" && target != next {
					return records{}, errors.New("conflicting CNAME targets in DNS answer")
				}
				target = next
			}
		}
		if target != "" && hasAddress {
			return records{}, errors.New("CNAME and address records coexist at the same owner")
		}
		out.merge(atOwner)
		if target == "" {
			return out, nil
		}
		out.CNAME = sortedUnique(append(out.CNAME, strings.TrimSuffix(target, ".")))
		owner = target
	}
	return records{}, errors.New("CNAME chain exceeds 16 links")
}

func lookupRecords(ctx context.Context, pool *resolverPool, name, avoid, pinned string, fresh bool) result {
	out := result{Domain: name, Status: "inconclusive", Reason: "query_failed", Resolver: pinned}
	for i, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		if qtype == dns.TypeCNAME && out.Records.any() {
			break
		}
		reply, err := pool.query(ctx, name, qtype, avoid, pinned, fresh)
		if err != nil {
			out.Detail = err.Error()
			if ctx.Err() != nil {
				out.Status, out.Reason = "cancelled", "cancelled"
			}
			return out
		}
		pinned, out.Resolver = reply.resolver, reply.resolver
		found, err := answerRecords(name, reply.msg)
		if err != nil {
			out.Reason, out.Detail = "invalid_answer", err.Error()
			return out
		}
		if out.Records.any() && found.any() && !slices.Equal(out.Records.CNAME, found.CNAME) {
			out.Reason = "inconsistent_answers"
			return out
		}
		if reply.msg.Rcode == dns.RcodeNameError {
			// An alias can exist even if its target does not. CNAME matches do
			// not establish address resolution or service availability.
			if len(found.CNAME) > 0 && len(found.A)+len(found.AAAA)+len(out.Records.A)+len(out.Records.AAAA) == 0 {
				out.Records.merge(found)
				out.Status, out.Reason = "valid", "cname_only"
				return out
			}
			if i != 0 || found.any() {
				out.Reason = "inconsistent_answers"
				return out
			}
			out.Status, out.Reason = "nxdomain", "name_does_not_exist"
			return out
		}
		out.Records.merge(found)
	}
	if out.Records.any() {
		out.Status, out.Reason = "valid", "dns_records"
		if len(out.Records.A)+len(out.Records.AAAA) == 0 {
			out.Reason = "cname_only"
		}
	} else {
		out.Status, out.Reason = "nodata", "no_address_or_cname_records"
	}
	return out
}

func (c *domainChecker) check(ctx context.Context, name string) result {
	out := lookupRecords(ctx, c.primary, name, "", "", false)
	if out.Status != "valid" {
		return out
	}
	if c.o.wildcard {
		c.checkWildcard(ctx, &out)
		if out.Status != "valid" {
			return out
		}
	}
	if c.o.confirm {
		confirmation := lookupRecords(ctx, c.confirmation, name, out.Resolver, "", true)
		out.ConfirmationResolver = confirmation.Resolver
		if confirmation.Status == "cancelled" {
			out.Status, out.Reason = "cancelled", "cancelled"
			return out
		}
		if confirmation.Status != "valid" || !out.Records.confirmedBy(confirmation.Records) {
			out.Status, out.Reason = "inconclusive", "confirmation_disagreement"
			out.Detail = confirmation.Status
			if confirmation.Detail != "" {
				out.Detail += ": " + confirmation.Detail
			}
			return out
		}
		out.Confirmed = true
	}
	return out
}

func (c *domainChecker) checkWildcard(ctx context.Context, out *result) {
	root, err := publicsuffix.EffectiveTLDPlusOne(out.Domain)
	if err != nil || root == out.Domain {
		return // Do not probe siblings of registrable roots or single labels.
	}
	_, parent, ok := strings.Cut(out.Domain, ".")
	if !ok || len(parent)+26 > 253 {
		return // A control name must still fit within the DNS length limit.
	}
	out.WildcardChecked = true
	var samples [2]records
	for i := range samples {
		probe, err := c.probeName(parent)
		if err != nil {
			out.Status, out.Reason, out.Detail = "inconclusive", "wildcard_check_failed", err.Error()
			return
		}
		sample := lookupRecords(ctx, c.primary, probe, "", out.Resolver, true)
		if sample.Status == "cancelled" {
			out.Status, out.Reason = "cancelled", "cancelled"
			return
		}
		if sample.Status == "inconclusive" {
			out.Status, out.Reason = "inconclusive", "wildcard_check_failed"
			out.Detail = fmt.Sprintf("%s: %s", sample.Reason, sample.Detail)
			return
		}
		samples[i] = sample.Records
	}
	if !samples[0].equal(samples[1]) {
		out.Status, out.Reason = "inconclusive", "wildcard_answers_vary"
		return
	}
	if samples[0].any() && out.Records.equal(samples[0]) {
		out.Status, out.Reason = "wildcard", "matches_wildcard_controls"
	}
}
