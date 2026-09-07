package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func cacheTestReply(rcode int, soa bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeA)
	m.Response = true
	m.Rcode = rcode
	if rcode == dns.RcodeSuccess {
		m.Answer = []dns.RR{aRecord("example.test", "192.0.2.1")}
	}
	if soa {
		m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Minttl: 20}}
	}
	return m
}

func TestCacheTTLAndIsolation(t *testing.T) {
	c := newReplyCache(2)
	now := time.Now()
	c.now = func() time.Time { return now }
	key := cacheKey{"127.0.0.1:53", "example.test.", dns.TypeA}
	original := cacheTestReply(dns.RcodeSuccess, false)
	c.put(key, original)
	original.Answer[0].Header().Ttl = 1
	now = now.Add(5 * time.Second)
	got, ok := c.get(key)
	if !ok || got.Answer[0].Header().Ttl != 55 {
		t.Fatalf("cached TTL or copy incorrect: %v %v", got, ok)
	}
	got.Answer = nil
	if next, _ := c.get(key); len(next.Answer) != 1 {
		t.Fatal("caller mutated cache")
	}
	if _, ok := c.get(cacheKey{"127.0.0.2:53", key.name, key.qtype}); ok {
		t.Fatal("cache crossed resolver boundary")
	}
	if _, ok := c.get(cacheKey{key.server, key.name, dns.TypeAAAA}); ok {
		t.Fatal("cache crossed record type boundary")
	}
	now = now.Add(55 * time.Second)
	if _, ok := c.get(key); ok {
		t.Fatal("expired reply returned")
	}
}

func TestNegativeCacheAndEviction(t *testing.T) {
	if cacheTTL(cacheTestReply(dns.RcodeNameError, false)) != 0 {
		t.Fatal("NXDOMAIN cached without SOA")
	}
	if cacheTTL(cacheTestReply(dns.RcodeNameError, true)) != 20 {
		t.Fatal("negative TTL did not use SOA minimum")
	}
	if cacheTTL(cacheTestReply(dns.RcodeServerFailure, true)) != 0 {
		t.Fatal("SERVFAIL cached")
	}
	if cacheTTL(cacheTestReply(dns.RcodeRefused, true)) != 0 {
		t.Fatal("REFUSED cached")
	}
	nodata := cacheTestReply(dns.RcodeSuccess, true)
	nodata.Answer = nil
	if cacheTTL(nodata) != 20 {
		t.Fatal("NODATA negative TTL incorrect")
	}
	nodata.Ns[0].Header().Name = "other.test."
	if cacheTTL(nodata) != 0 {
		t.Fatal("accepted unrelated SOA")
	}
	zero := cacheTestReply(dns.RcodeSuccess, false)
	zero.Answer[0].Header().Ttl = 0
	if cacheTTL(zero) != 0 {
		t.Fatal("zero TTL cached")
	}
	c := newReplyCache(2)
	first := cacheKey{"server", "one.test.", dns.TypeA}
	second := cacheKey{"server", "two.test.", dns.TypeA}
	third := cacheKey{"server", "three.test.", dns.TypeA}
	c.put(first, cacheTestReply(dns.RcodeSuccess, false))
	c.put(second, cacheTestReply(dns.RcodeSuccess, false))
	_, _ = c.get(first)
	c.put(third, cacheTestReply(dns.RcodeSuccess, false))
	if _, ok := c.get(second); ok || len(c.entries) != 2 {
		t.Fatal("cache capacity or LRU eviction incorrect")
	}
}

func TestConfirmationBypassesCache(t *testing.T) {
	var calls atomic.Int32
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		calls.Add(1)
		replyWith(w, req, dns.RcodeSuccess, aRecord(req.Question[0].Name, "192.0.2.1"))
	})
	o := testOptions(t)
	o.cacheSize = 8
	transport := newDNSTransport(o)
	for _, fresh := range []bool{false, false, true} {
		if _, err := transport.query(context.Background(), "example.test", dns.TypeA, server, fresh); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 || transport.cacheHits.Load() != 1 {
		t.Fatalf("calls=%d hits=%d", calls.Load(), transport.cacheHits.Load())
	}
}

func TestRateLimitAppliesToWireQueries(t *testing.T) {
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) { replyWith(w, req, dns.RcodeNameError) })
	o := testOptions(t)
	o.qps = 20
	transport := newDNSTransport(o)
	start := time.Now()
	for range 2 {
		if _, err := transport.query(context.Background(), "example.test", dns.TypeA, server, true); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("rate limit was not applied")
	}
}

// Compares the same repeated lookup with and without caching against loopback
// DNS. This measures repeated-query savings, not Internet resolver throughput.
func BenchmarkRepeatedDNS(b *testing.B) {
	for _, size := range []int{0, 4096} {
		b.Run(fmt.Sprintf("cache_%d", size), func(b *testing.B) {
			server := startDNSServer(b, func(w dns.ResponseWriter, req *dns.Msg) {
				replyWith(w, req, dns.RcodeSuccess, aRecord(req.Question[0].Name, "192.0.2.1"))
			})
			o := testOptions(b)
			o.cacheSize = size
			transport := newDNSTransport(o)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := transport.query(context.Background(), "example.test", dns.TypeA, server, false); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(transport.exchanges.Load())/float64(b.N), "queries/op")
		})
	}
}
