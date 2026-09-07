package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func fakePositive(_ context.Context, name string) result {
	return result{Domain: name, Status: "valid", Reason: "dns_records", Records: records{A: []string{"192.0.2.1"}}}
}

func TestPipelineNormalizesAndCounts(t *testing.T) {
	o := testOptions(t)
	o.unique, o.jsonl = true, true
	var out bytes.Buffer
	input := "# domains\r\n\r\nExample.TEST.\r\nhttps://example.test/path\r\ninvalid..test\r\nother.test\r\n"
	stats, err := processInput(context.Background(), o, strings.NewReader(input), &out, io.Discard, fakePositive)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Lines != 6 || stats.Ignored != 2 || stats.Submitted != 4 || stats.Completed != 4 || stats.Outcomes["valid"] != 2 || stats.Outcomes["invalid_input"] != 1 || stats.Outcomes["duplicate"] != 1 {
		t.Fatalf("incorrect counts: %+v", stats)
	}
	decoder := json.NewDecoder(&out)
	counts := make(map[string]int)
	for {
		var r result
		if err := decoder.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		counts[r.Status]++
		if r.Input == "" {
			t.Fatal("original input missing")
		}
	}
	if counts["valid"] != 2 || counts["duplicate"] != 1 || counts["invalid_input"] != 1 {
		t.Fatalf("incorrect JSON outcomes: %v", counts)
	}
}

func TestUniqueLimitStopsWithoutSilentlyDroppingNames(t *testing.T) {
	o := testOptions(t)
	o.unique, o.uniqueLimit, o.jsonl = true, 1, true
	var out bytes.Buffer
	stats, err := processInput(context.Background(), o, strings.NewReader("one.test\none.test\ntwo.test\nthree.test\n"), &out, io.Discard, fakePositive)
	if err == nil || stats.Lines != 3 || stats.Completed != 3 || stats.Outcomes["inconclusive"] != 1 || !strings.Contains(out.String(), "unique_limit") {
		t.Fatalf("deduplication limit: %+v %v %s", stats, err, out.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestPipelineReturnsIOErrors(t *testing.T) {
	o := testOptions(t)
	_, err := processInput(context.Background(), o, failingReader{}, io.Discard, io.Discard, fakePositive)
	if err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("read error lost: %v", err)
	}
	stats, err := processInput(context.Background(), o, strings.NewReader(strings.Repeat("example.test\n", 10000)), failingWriter{}, io.Discard, fakePositive)
	if err == nil || !strings.Contains(err.Error(), "write failed") || stats.Submitted != stats.Completed {
		t.Fatalf("write error/drain: %+v %v", stats, err)
	}
	_, err = processInput(context.Background(), o, strings.NewReader(strings.Repeat("x", maxInputLine+1)), io.Discard, io.Discard, fakePositive)
	if err == nil {
		t.Fatal("scanner length error lost")
	}
}

func TestCancellationClosesBlockedInput(t *testing.T) {
	o := testOptions(t)
	r, w := io.Pipe()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := processInput(ctx, o, r, io.Discard, io.Discard, fakePositive)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation not returned: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("input scanner remained blocked")
	}
}

func TestResultFormats(t *testing.T) {
	r := result{Input: "example.test", Domain: "example.test", Status: "valid", Reason: "dns_records", Records: records{A: []string{"192.0.2.1"}, AAAA: []string{"2001:db8::1"}, CNAME: []string{"target.test"}}}
	var out bytes.Buffer
	if err := writeResult(&out, options{}, r); err != nil || out.String() != "example.test\n" {
		t.Fatalf("plain: %q %v", out.String(), err)
	}
	out.Reset()
	if err := writeResult(&out, options{showIP: true}, r); err != nil || out.String() != "example.test : [A:192.0.2.1] [AAAA:2001:db8::1] [CNAME:target.test]\n" {
		t.Fatalf("records: %q %v", out.String(), err)
	}
	out.Reset()
	r.Status, r.Reason = "nxdomain", "name_does_not_exist"
	r.Records = records{}
	if err := writeResult(&out, options{jsonl: true}, r); err != nil {
		t.Fatal(err)
	}
	const want = "{\"input\":\"example.test\",\"domain\":\"example.test\",\"status\":\"nxdomain\",\"reason\":\"name_does_not_exist\",\"records\":{},\"confirmed\":false,\"wildcard_checked\":false}\n"
	if out.String() != want {
		t.Fatalf("JSONL: %s", out.String())
	}
}

func cliTestServer(t *testing.T) string {
	return startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Name == "absent.test." {
			replyWith(w, req, dns.RcodeNameError)
			return
		}
		var answer []dns.RR
		if req.Question[0].Qtype == dns.TypeA {
			answer = []dns.RR{aRecord(req.Question[0].Name, "192.0.2.1")}
		}
		replyWith(w, req, dns.RcodeSuccess, answer...)
	})
}

func cliTestArgs(server string) []string {
	return []string{"-l", server, "--confirm=false", "--wildcard=false", "--rate-limit", "1000000"}
}

func TestCLIOutputFilesAndStats(t *testing.T) {
	server := cliTestServer(t)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.txt"), filepath.Join(dir, "output.txt")
	if err := os.WriteFile(input, []byte("Example.test\r\nabsent.test\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"--append", "--overwrite"} {
		if err := os.WriteFile(output, []byte("previous\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		args := append(cliTestArgs(server), "--input", input, "-o", output, mode, "--show-ip", "--show-stats")
		if code := run(context.Background(), args, strings.NewReader("unused.test"), &stdout, &stderr); code != 0 {
			t.Fatalf("exit=%d %s", code, stderr.String())
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		want := stdout.String()
		if mode == "--append" {
			want = "previous\n" + want
		}
		if string(data) != want || !strings.Contains(stderr.String(), "Valid: 1 | NXDOMAIN: 1") || strings.Contains(stdout.String(), "Queries:") {
			t.Fatalf("stdout=%q stderr=%q file=%q", stdout.String(), stderr.String(), data)
		}
	}
}

func TestCLIProtectsInputAndReportsFailures(t *testing.T) {
	server := cliTestServer(t)
	input := filepath.Join(t.TempDir(), "input.txt")
	const original = "example.test\n"
	if err := os.WriteFile(input, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(cliTestArgs(server), "--input", input, "-o", input, "--overwrite")
	if code := run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); code != 1 {
		t.Fatalf("same-file output exit=%d", code)
	}
	data, err := os.ReadFile(input)
	if err != nil || string(data) != original {
		t.Fatal("input file was modified")
	}
	if code := run(context.Background(), append(cliTestArgs(server), "-u", "example.test"), strings.NewReader(""), failingWriter{}, io.Discard); code != 1 {
		t.Fatalf("flush error exit=%d", code)
	}
	if code := run(context.Background(), append(cliTestArgs(server), "--input", "missing-input"), strings.NewReader(""), io.Discard, io.Discard); code != 1 {
		t.Fatalf("missing input exit=%d", code)
	}
	for _, arg := range []string{"--help", "--version"} {
		if code := run(context.Background(), []string{arg}, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
			t.Fatalf("%s exit=%d", arg, code)
		}
	}
	for _, args := range [][]string{{"--unknown"}, {"--url", "bad..test"}, {"--dnsServers="}, {"--dnsFile="}, {"--output="}} {
		if code := run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); code != 2 {
			t.Fatalf("args=%v exit=%d", args, code)
		}
	}
	if code := run(context.Background(), cliTestArgs(server), strings.NewReader("bad..test\n"), io.Discard, io.Discard); code != 1 {
		t.Fatalf("invalid input exit=%d", code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := run(ctx, cliTestArgs(server), strings.NewReader("example.test\n"), io.Discard, io.Discard); code != 130 {
		t.Fatalf("cancelled exit=%d", code)
	}
}

func TestCLIJSONLSeparatesSummary(t *testing.T) {
	server := cliTestServer(t)
	var stdout, stderr bytes.Buffer
	args := append(cliTestArgs(server), "--jsonl", "--show-stats")
	if code := run(context.Background(), args, strings.NewReader("absent.test\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d %s", code, stderr.String())
	}
	var r result
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &r); err != nil || r.Status != "nxdomain" {
		t.Fatalf("result: %+v %v", r, err)
	}
	var summary struct {
		Stats runStats `json:"stats"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &summary); err != nil || summary.Stats.Completed != 1 || summary.Stats.Outcomes["nxdomain"] != 1 {
		t.Fatalf("summary: %+v %v", summary, err)
	}
}

func TestWorkersAndResultsStayBounded(t *testing.T) {
	o := testOptions(t)
	o.workers = 3
	var active, peak atomic.Int32
	check := func(ctx context.Context, name string) result {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		defer active.Add(-1)
		return fakePositive(ctx, name)
	}
	stats, err := processInput(context.Background(), o, strings.NewReader(strings.Repeat("example.test\n", 1000)), io.Discard, io.Discard, check)
	if err != nil || stats.Completed != 1000 || stats.Submitted != 1000 || peak.Load() > 3 {
		t.Fatalf("worker limits: %+v peak=%d err=%v", stats, peak.Load(), err)
	}
}
