package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const maxInputLine = 64 * 1024

// normalizeInput accepts hostnames, including internal single-label names,
// and HTTP(S) URLs. A blank result without an error denotes an ignored line.
func normalizeInput(raw string) (string, error) {
	name := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if name == "" || strings.HasPrefix(name, "#") {
		return "", nil
	}
	if strings.Contains(name, "://") {
		u, err := url.Parse(name)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return "", errors.New("expected a domain or HTTP(S) URL without credentials")
		}
		if port := u.Port(); port != "" {
			if _, err := validPort(port); err != nil {
				return "", err
			}
		}
		name = u.Hostname()
	}
	name = strings.TrimSuffix(name, ".")
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("IP literals are not domain names")
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", errors.New("invalid internationalized domain name")
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", errors.New("domain name must contain 1 to 253 ASCII bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label length or hyphen placement")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("domain labels may only contain letters, digits and hyphens")
			}
		}
	}
	return ascii, nil
}

func validPort(port string) (string, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", errors.New("port must be between 1 and 65535")
	}
	return strconv.Itoa(p), nil
}

func normalizeResolver(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if ip, err := netip.ParseAddr(raw); err == nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		if ip, err := netip.ParseAddr(raw[1 : len(raw)-1]); err == nil {
			return net.JoinHostPort(ip.String(), "53"), nil
		}
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("invalid resolver %q: use an IP, IP:port or [IPv6]:port", raw)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("resolver %q must use an IP address", raw)
	}
	port, err = validPort(port)
	if err != nil {
		return "", fmt.Errorf("resolver %q: %w", raw, err)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func parseResolverList(raw string) ([]string, error) {
	var servers []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimPrefix(raw, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, value := range strings.Split(line, ",") {
			if strings.TrimSpace(value) == "" {
				return nil, errors.New("empty entry in resolver list")
			}
			server, err := normalizeResolver(value)
			if err != nil {
				return nil, err
			}
			if !seen[server] {
				servers = append(servers, server)
				seen[server] = true
			}
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("resolver list is empty")
	}
	return servers, nil
}

func loadResolvers(o options) ([]string, error) {
	if o.resolverList != "" {
		return parseResolverList(o.resolverList)
	}
	if o.resolverFile != "" {
		return readResolverFile(o.resolverFile)
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		servers, err := readResolverFile(filepath.Join(homeDir, ".dmut", "resolvers.txt"))
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return servers, err
		}
	}
	return []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53", "9.9.9.9:53"}, nil
}

func readResolverFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), maxInputLine)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read resolvers: %w", err)
	}
	return parseResolverList(strings.Join(lines, "\n"))
}
