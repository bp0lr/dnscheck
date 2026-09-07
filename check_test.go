package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func aaaaRecord(name, ip string) dns.RR {
	return &dns.AAAA{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP(ip)}
}

func cnameRecord(name, target string) dns.RR {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: dns.Fqdn(target)}
}

func TestDNSClassification(t *testing.T) {
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		name, typ := req.Question[0].Name, req.Question[0].Qtype
		var answer []dns.RR
		switch name {
		case "absent.test.":
			replyWith(w, req, dns.RcodeNameError)
			return
		case "failure.test.":
			replyWith(w, req, dns.RcodeServerFailure)
			return
		case "v4.test.":
			if typ == dns.TypeA {
				answer = []dns.RR{aRecord(name, "192.0.2.1")}
			}
		case "v6.test.":
			if typ == dns.TypeAAAA {
				answer = []dns.RR{aaaaRecord(name, "2001:db8::1")}
			}
		case "dual.test.":
			if typ == dns.TypeA {
				answer = []dns.RR{aRecord(name, "192.0.2.1")}
			}
			if typ == dns.TypeAAAA {
				answer = []dns.RR{aaaaRecord(name, "2001:db8::1")}
			}
		case "alias.test.":
			answer = []dns.RR{cnameRecord(name, "v4.test")}
			if typ == dns.TypeA {
				answer = append(answer, aRecord("v4.test", "192.0.2.1"))
			}
		case "cname.test.":
			if typ == dns.TypeCNAME {
				answer = []dns.RR{cnameRecord(name, "target.test")}
			}
		case "dangling.test.":
			replyWith(w, req, dns.RcodeNameError, cnameRecord(name, "absent.test"))
			return
		case "loop.test.":
			answer = []dns.RR{cnameRecord(name, "loop.test")}
		case "unrelated.test.":
			answer = []dns.RR{aRecord("someone-else.test", "192.0.2.9")}
		case "wrongtype.test.":
			if typ == dns.TypeA {
				answer = []dns.RR{aaaaRecord(name, "2001:db8::1")}
			} else {
				answer = []dns.RR{aRecord(name, "192.0.2.1")}
			}
		case "root-alias.test.":
			answer = []dns.RR{cnameRecord(name, ".")}
		case "changing-alias.test.":
			target := "one.test"
			if typ == dns.TypeAAAA {
				target = "two.test"
			}
			answer = []dns.RR{cnameRecord(name, target)}
		case "conflict.test.":
			if typ == dns.TypeA {
				answer = []dns.RR{aRecord(name, "192.0.2.1")}
			} else {
				replyWith(w, req, dns.RcodeNameError)
				return
			}
		}
		replyWith(w, req, dns.RcodeSuccess, answer...)
	})
	o := testOptions(t)
	o.confirm, o.wildcard = false, false
	checker := newDomainChecker(o, []string{server}, nil)
	tests := []struct {
		name, status   string
		a, aaaa, cname int
	}{
		{"v4.test", "valid", 1, 0, 0}, {"v6.test", "valid", 0, 1, 0}, {"dual.test", "valid", 1, 1, 0},
		{"alias.test", "valid", 1, 0, 1}, {"cname.test", "valid", 0, 0, 1}, {"dangling.test", "valid", 0, 0, 1},
		{"absent.test", "nxdomain", 0, 0, 0}, {"empty.test", "nodata", 0, 0, 0},
		{"failure.test", "inconclusive", 0, 0, 0}, {"loop.test", "inconclusive", 0, 0, 0},
		{"unrelated.test", "nodata", 0, 0, 0}, {"conflict.test", "inconclusive", 1, 0, 0},
		{"wrongtype.test", "nodata", 0, 0, 0}, {"root-alias.test", "inconclusive", 0, 0, 0},
		{"changing-alias.test", "inconclusive", 0, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := checker.check(context.Background(), tt.name)
			if r.Status != tt.status || len(r.Records.A) != tt.a || len(r.Records.AAAA) != tt.aaaa || len(r.Records.CNAME) != tt.cname {
				t.Fatalf("unexpected classification: %+v", r)
			}
		})
	}
}

func TestWildcardClassification(t *testing.T) {
	for _, scenario := range []string{"matching", "explicit", "ipv6", "rotating", "refused", "negative", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			var probes atomic.Int32
			server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				name, typ := req.Question[0].Name, req.Question[0].Qtype
				control := strings.HasPrefix(name, "dnscheck-")
				if control && scenario == "refused" {
					replyWith(w, req, dns.RcodeRefused)
					return
				}
				if control && scenario == "negative" {
					replyWith(w, req, dns.RcodeNameError)
					return
				}
				if control && scenario == "empty" {
					replyWith(w, req, dns.RcodeSuccess)
					return
				}
				var answer []dns.RR
				if scenario == "ipv6" {
					if typ == dns.TypeAAAA {
						answer = []dns.RR{aaaaRecord(name, "2001:db8::1")}
					}
				} else if typ == dns.TypeA {
					ip := "192.0.2.1"
					if scenario == "explicit" && !control {
						ip = "192.0.2.2"
					}
					if scenario == "rotating" && control && probes.Add(1)%2 == 0 {
						ip = "192.0.2.2"
					}
					answer = []dns.RR{aRecord(name, ip)}
				}
				replyWith(w, req, dns.RcodeSuccess, answer...)
			})
			o := testOptions(t)
			o.confirm = false
			checker := newDomainChecker(o, []string{server}, nil)
			r := checker.check(context.Background(), "host.nested.example.test")
			want := map[string]string{"matching": "wildcard", "explicit": "valid", "ipv6": "wildcard", "rotating": "inconclusive", "refused": "inconclusive", "negative": "valid", "empty": "valid"}[scenario]
			if r.Status != want || !r.WildcardChecked {
				t.Fatalf("expected %s, got %+v", want, r)
			}
		})
	}
}

func TestConfirmationRequiresRelevantData(t *testing.T) {
	primary := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		var answer []dns.RR
		if req.Question[0].Qtype == dns.TypeA {
			answer = []dns.RR{aRecord(req.Question[0].Name, "192.0.2.1")}
		}
		replyWith(w, req, dns.RcodeSuccess, answer...)
	})
	for _, mode := range []string{"empty", "negative", "different_address", "different_type"} {
		t.Run(mode, func(t *testing.T) {
			confirmation := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
				if mode == "negative" {
					replyWith(w, req, dns.RcodeNameError)
					return
				}
				var answer []dns.RR
				if mode == "different_address" && req.Question[0].Qtype == dns.TypeA {
					answer = []dns.RR{aRecord(req.Question[0].Name, "192.0.2.2")}
				}
				if mode == "different_type" && req.Question[0].Qtype == dns.TypeAAAA {
					answer = []dns.RR{aaaaRecord(req.Question[0].Name, "2001:db8::1")}
				}
				replyWith(w, req, dns.RcodeSuccess, answer...)
			})
			o := testOptions(t)
			o.wildcard = false
			r := newDomainChecker(o, []string{primary}, []string{confirmation}).check(context.Background(), "example.test")
			want := "inconclusive"
			if mode == "different_address" {
				want = "valid"
			}
			if r.Status != want || r.Confirmed != (want == "valid") || r.ConfirmationResolver != confirmation {
				t.Fatalf("confirmation result: %+v", r)
			}
		})
	}
}

func TestRootAndInternalNamesDoNotProbePublicSuffix(t *testing.T) {
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		if strings.HasPrefix(req.Question[0].Name, "dnscheck-") {
			t.Error("unexpected wildcard control")
		}
		var answer []dns.RR
		if req.Question[0].Qtype == dns.TypeA {
			answer = []dns.RR{aRecord(req.Question[0].Name, "192.0.2.1")}
		}
		replyWith(w, req, dns.RcodeSuccess, answer...)
	})
	o := testOptions(t)
	o.confirm = false
	for _, name := range []string{"example.test", "printer"} {
		r := newDomainChecker(o, []string{server}, nil).check(context.Background(), name)
		if r.Status != "valid" || r.WildcardChecked {
			t.Fatalf("unexpected root classification: %+v", r)
		}
	}
}
