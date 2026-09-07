package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type dnsReply struct {
	msg      *dns.Msg
	resolver string
}

type dnsTransport struct {
	timeout   time.Duration
	limiter   *rate.Limiter
	exchanges atomic.Uint64
}

func newDNSTransport(o options) *dnsTransport {
	return &dnsTransport{timeout: o.timeout, limiter: rate.NewLimiter(rate.Limit(o.qps), 1)}
}

func (t *dnsTransport) exchange(ctx context.Context, name string, qtype uint16, server, network string) (*dns.Msg, error) {
	if err := t.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	client := &dns.Client{Net: network, Timeout: t.timeout}
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Closing the socket also interrupts an in-progress read on cancellation.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.SetEdns0(1232, false)
	t.exchanges.Add(1)
	resp, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if resp == nil || !resp.Response || resp.Opcode != dns.OpcodeQuery || len(resp.Question) != 1 ||
		dns.CanonicalName(resp.Question[0].Name) != dns.CanonicalName(msg.Question[0].Name) ||
		resp.Question[0].Qtype != qtype || resp.Question[0].Qclass != dns.ClassINET {
		return nil, errors.New("resolver returned a mismatched DNS response")
	}
	return resp, nil
}

func (t *dnsTransport) query(ctx context.Context, name string, qtype uint16, server string, fresh bool) (*dns.Msg, error) {
	resp, err := t.exchange(ctx, name, qtype, server, "udp")
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		resp, err = t.exchange(ctx, name, qtype, server, "tcp")
		if err != nil {
			return nil, fmt.Errorf("TCP fallback: %w", err)
		}
		if resp.Truncated {
			return nil, errors.New("truncated TCP response")
		}
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		code := dns.RcodeToString[resp.Rcode]
		if code == "" {
			code = fmt.Sprintf("RCODE%d", resp.Rcode)
		}
		return nil, fmt.Errorf("DNS %s", code)
	}
	return resp, nil
}

type resolverState struct {
	address    string
	failures   int
	retryAfter time.Time
}

type resolverPool struct {
	transport             *dnsTransport
	mu                    sync.Mutex
	servers               []resolverState
	next, attempts, limit int
	cooldown              time.Duration
	now                   func() time.Time
}

func newResolverPool(servers []string, o options, transport *dnsTransport) *resolverPool {
	p := &resolverPool{transport: transport, attempts: o.attempts, limit: o.errorLimit, cooldown: o.cooldown, now: time.Now}
	for _, server := range servers {
		p.servers = append(p.servers, resolverState{address: server})
	}
	return p
}

func (p *resolverPool) pick(avoid, pinned string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for pass := 0; pass < 2; pass++ {
		for offset := 0; offset < len(p.servers); offset++ {
			i := (p.next + offset) % len(p.servers)
			s := p.servers[i]
			if now.Before(s.retryAfter) || pinned != "" && s.address != pinned || pass == 0 && s.address == avoid {
				continue
			}
			p.next = (i + 1) % len(p.servers)
			return i, nil
		}
	}
	return 0, errors.New("no eligible resolver: configured servers are cooling down or unavailable")
}

func (p *resolverPool) report(index int, success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &p.servers[index]
	if success {
		s.failures = 0
		s.retryAfter = time.Time{}
		return
	}
	s.failures++
	if s.failures >= p.limit {
		s.retryAfter = p.now().Add(p.cooldown)
	}
}

// query rotates on failure. pinned keeps related wildcard probes on the same
// resolver; avoid prefers a different server during independent confirmation.
func (p *resolverPool) query(ctx context.Context, name string, qtype uint16, avoid, pinned string, fresh bool) (dnsReply, error) {
	var last error
	for attempt := 0; attempt < p.attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return dnsReply{}, err
		}
		i, err := p.pick(avoid, pinned)
		if err != nil {
			return dnsReply{}, errors.Join(last, err)
		}
		server := p.servers[i].address // Addresses are immutable after construction.
		resp, err := p.transport.query(ctx, name, qtype, server, fresh)
		if err == nil {
			p.report(i, true)
			return dnsReply{msg: resp, resolver: server}, nil
		}
		if ctx.Err() != nil {
			return dnsReply{}, ctx.Err()
		}
		p.report(i, false)
		last = fmt.Errorf("%s via %s: %w", dns.TypeToString[qtype], server, err)
		avoid = server
	}
	return dnsReply{}, last
}
