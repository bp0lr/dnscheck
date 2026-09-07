package main

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testOptions(t testing.TB) options {
	t.Helper()
	o, _, err := parseOptions(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	o.qps = 1000000
	o.attempts = 1
	o.timeout = time.Second
	o.cacheSize = 0
	return o
}

// Both transports share a loopback port. Tests never require public DNS.
func startDNSServer(t testing.TB, handler dns.HandlerFunc) string {
	t.Helper()
	var tcp net.Listener
	var udp net.PacketConn
	var err error
	for range 10 {
		udp, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err = net.Listen("tcp", udp.LocalAddr().String())
		if err == nil {
			break
		}
		_ = udp.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	readyUDP, readyTCP := make(chan struct{}), make(chan struct{})
	servers := []*dns.Server{
		{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { close(readyUDP) }},
		{Listener: tcp, Handler: handler, NotifyStartedFunc: func() { close(readyTCP) }},
	}
	done := make(chan error, 2)
	for _, server := range servers {
		go func() { done <- server.ActivateAndServe() }()
	}
	for _, ready := range []chan struct{}{readyUDP, readyTCP} {
		select {
		case <-ready:
		case <-time.After(3 * time.Second):
			t.Fatal("local DNS server did not start")
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, server := range servers {
			if err := server.ShutdownContext(ctx); err != nil {
				t.Errorf("shutdown DNS server: %v", err)
			}
		}
		for range servers {
			if err := <-done; err != nil {
				t.Errorf("DNS server: %v", err)
			}
		}
	})
	return tcp.Addr().String()
}

func replyWith(w dns.ResponseWriter, req *dns.Msg, rcode int, records ...dns.RR) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = rcode
	m.Answer = records
	_ = w.WriteMsg(m)
}

func aRecord(name, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}
}

func TestResolverFallbackAndHealth(t *testing.T) {
	var failedCalls atomic.Int32
	bad := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		failedCalls.Add(1)
		replyWith(w, req, dns.RcodeServerFailure)
	})
	good := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		replyWith(w, req, dns.RcodeSuccess, aRecord(req.Question[0].Name, "192.0.2.1"))
	})
	o := testOptions(t)
	o.attempts, o.errorLimit = 2, 1
	p := newResolverPool([]string{bad, good}, o, newDNSTransport(o))
	resp, err := p.query(context.Background(), "example.test", dns.TypeA, "", "", false)
	if err != nil || resp.resolver != good || failedCalls.Load() != 1 {
		t.Fatalf("fallback: resolver=%s err=%v attempts=%d", resp.resolver, err, failedCalls.Load())
	}
	if _, err := p.query(context.Background(), "example.test", dns.TypeA, "", bad, false); err == nil {
		t.Fatal("resolver did not enter cooldown")
	}
	p.now = func() time.Time { return time.Now().Add(o.cooldown * 2) }
	if _, err := p.pick("", bad); err != nil {
		t.Fatalf("resolver did not recover after cooldown: %v", err)
	}
}

func TestTruncatedReplyUsesTCP(t *testing.T) {
	var tcpCalls atomic.Int32
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		if strings.HasPrefix(w.RemoteAddr().Network(), "udp") {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		tcpCalls.Add(1)
		replyWith(w, req, dns.RcodeSuccess, aRecord(req.Question[0].Name, "192.0.2.2"))
	})
	o := testOptions(t)
	transport := newDNSTransport(o)
	resp, err := transport.query(context.Background(), "example.test", dns.TypeA, server, false)
	if err != nil || len(resp.Answer) != 1 || tcpCalls.Load() != 1 || transport.exchanges.Load() != 2 {
		t.Fatalf("TCP fallback: %v, calls=%d", err, tcpCalls.Load())
	}
}

func TestTCPFailureIsReturned(t *testing.T) {
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	o := testOptions(t)
	_, err := newDNSTransport(o).query(context.Background(), "example.test", dns.TypeA, server, false)
	if err == nil || !strings.Contains(err.Error(), "truncated TCP") {
		t.Fatalf("expected truncated TCP error, got %v", err)
	}
}

func TestCancellationInterruptsDNSRead(t *testing.T) {
	received := make(chan struct{})
	var once sync.Once
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		once.Do(func() { close(received) })
	})
	o := testOptions(t)
	o.timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := newDNSTransport(o).query(ctx, "example.test", dns.TypeA, server, false)
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("query not received")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt network read")
	}
}

func TestNegativeAnswersAndConcurrentSelection(t *testing.T) {
	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) { replyWith(w, req, dns.RcodeNameError) })
	o := testOptions(t)
	p := newResolverPool([]string{server}, o, newDNSTransport(o))
	var wg sync.WaitGroup
	for range 25 {
		wg.Go(func() {
			resp, err := p.query(context.Background(), "absent.test", dns.TypeA, "", "", false)
			if err != nil || resp.msg.Rcode != dns.RcodeNameError {
				t.Errorf("NXDOMAIN should be a successful DNS exchange: %v", err)
			}
		})
	}
	wg.Wait()
	if p.servers[0].failures != 0 {
		t.Fatal("negative answers counted as resolver failures")
	}
}
