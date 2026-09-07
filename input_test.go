package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeInput(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"  Example.COM.\r", "example.com"},
		{"https://EXAMPLE.com:443/a?q=1#x", "example.com"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"printer", "printer"}, {"", ""}, {"  # comment", ""},
		{"\ufeffExample.com", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := normalizeInput(tt.raw)
			if err != nil || got != tt.want {
				t.Fatalf("normalizeInput(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
			}
		})
	}
	for _, raw := range []string{".", "foo..example", "-foo.example", "foo-.example", "foo_bar.example", "a b.example", "127.0.0.1", "::1", "https://[::1]/", "ftp://example.com", "https://user:pass@example.com", "https://example.com:99999", "example.com/path", "example.com:53", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "a"} {
		if _, err := normalizeInput(raw); err == nil {
			t.Errorf("accepted invalid input %q", raw)
		}
	}
}

func TestResolverInput(t *testing.T) {
	servers, err := parseResolverList("\ufeff# resolvers\r\n 1.1.1.1 \r\n1.1.1.1:53, [::1]:5353,2001:db8::1\n[2001:db8::1]\n")
	if err != nil || strings.Join(servers, ",") != "1.1.1.1:53,[::1]:5353,[2001:db8::1]:53" {
		t.Fatalf("unexpected resolver parsing: %v, %v", servers, err)
	}
	for _, raw := range []string{"", "# empty", "example.com", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1,", "1.1.1.1,,8.8.8.8", "[::1]:x"} {
		if _, err := parseResolverList(raw); err == nil {
			t.Errorf("accepted invalid resolvers %q", raw)
		}
	}
}

func TestResolverPrecedence(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(file, []byte("127.0.0.1:5353\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		o    options
		want string
	}{
		{options{resolverFile: file}, "127.0.0.1:5353"},
		{options{resolverFile: "missing", resolverList: "[::1]:5354"}, "[::1]:5354"},
	} {
		servers, err := loadResolvers(tt.o)
		if err != nil || len(servers) != 1 || servers[0] != tt.want {
			t.Fatalf("loadResolvers: %v %v", servers, err)
		}
	}
	if _, err := loadResolvers(options{resolverFile: "missing"}); err == nil {
		t.Fatal("missing resolver file accepted")
	}
}

func TestOptions(t *testing.T) {
	for _, args := range [][]string{{"--workers", "0"}, {"--workers", "151"}, {"--dns-timeout", "-1"}, {"--dns-timeout", "10001"}, {"--dns-retries", "0"}, {"--dns-retries", "11"}, {"--dns-errorLimit", "0"}, {"--dns-cooldown", "0s"}, {"--rate-limit", "0"}, {"--cache-size", "-1"}, {"--unique-limit", "0"}, {"--url", "example.com", "--input", "in.txt"}, {"--url="}, {"--input="}, {"--append", "--overwrite", "-o", "out"}, {"--overwrite"}, {"--confirm=false", "--confirm-resolvers", "1.1.1.1"}, {"extra"}, {"--unknown"}} {
		if _, _, err := parseOptions(args, &bytes.Buffer{}); err == nil {
			t.Errorf("accepted invalid args: %v", args)
		}
	}
	for _, arg := range []string{"--help", "-h", "--version"} {
		var out bytes.Buffer
		if _, handled, err := parseOptions([]string{arg}, &out); err != nil || !handled || out.Len() == 0 {
			t.Fatalf("%s: handled=%v error=%v output=%q", arg, handled, err, out.String())
		}
	}
	o, handled, err := parseOptions([]string{"-w", "2", "-u", "example.com", "--dns-retries", "1"}, &bytes.Buffer{})
	if err != nil || handled || o.workers != 2 || o.attempts != 1 || o.timeout.Milliseconds() != 500 {
		t.Fatalf("unexpected options: %+v, %v", o, err)
	}
}
