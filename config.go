package main

import (
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"time"

	"github.com/spf13/pflag"
)

var version = "dev"

type options struct {
	workers, attempts, errorLimit int
	timeout, cooldown             time.Duration
	input, target, output         string
	resolverFile, resolverList    string
	confirmResolvers              string
	verbose, showIP, showStats    bool
	jsonl, overwrite              bool
	confirm, wildcard, unique     bool
	uniqueLimit, cacheSize, qps   int
}

func parseOptions(args []string, stdout io.Writer) (options, bool, error) {
	var o options
	var help, showVersion, appendOutput bool
	var timeoutMS int
	f := pflag.NewFlagSet("dnscheck", pflag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.IntVarP(&o.workers, "workers", "w", 25, "Concurrent workers (1-150)")
	f.StringVarP(&o.target, "url", "u", "", "Check a domain name or HTTP(S) URL")
	f.StringVar(&o.input, "input", "", "Read input from a file instead of stdin")
	f.StringVarP(&o.output, "output", "o", "", "Write results to a file as well as stdout")
	f.BoolVar(&appendOutput, "append", false, "Append to the output file (default behavior)")
	f.BoolVar(&o.overwrite, "overwrite", false, "Replace the output file instead of appending")
	f.StringVarP(&o.resolverFile, "dnsFile", "s", "", "Read resolver IP addresses from a file")
	f.StringVarP(&o.resolverList, "dnsServers", "l", "", "Comma-separated resolver IP addresses, with optional ports")
	f.IntVar(&timeoutMS, "dns-timeout", 500, "Timeout per network exchange in milliseconds (1-10000)")
	f.IntVar(&o.attempts, "dns-retries", 3, "Total attempts per DNS query (1-10)")
	f.IntVar(&o.errorLimit, "dns-errorLimit", 25, "Consecutive failures before a resolver cooldown")
	f.DurationVar(&o.cooldown, "dns-cooldown", 30*time.Second, "Cooldown after repeated resolver failures")
	f.BoolVar(&o.confirm, "confirm", true, "Confirm positive results with another lookup")
	f.StringVar(&o.confirmResolvers, "confirm-resolvers", "", "Confirmation resolver IPs (default: configured resolver pool)")
	f.BoolVar(&o.wildcard, "wildcard", true, "Check positive results for wildcard matches")
	f.BoolVar(&o.unique, "unique", false, "Process each normalized domain once")
	f.IntVar(&o.uniqueLimit, "unique-limit", 100000, "Maximum names retained by --unique; fail if exceeded")
	f.IntVar(&o.cacheSize, "cache-size", 4096, "Maximum cached DNS replies (0 disables caching)")
	f.IntVar(&o.qps, "rate-limit", 100, "Maximum DNS network exchanges per second")
	f.BoolVar(&o.jsonl, "jsonl", false, "Emit every outcome as a JSON object on its own line")
	f.BoolVar(&o.showIP, "show-ip", false, "Include A, AAAA and CNAME records in plain output")
	f.BoolVar(&o.showStats, "show-stats", false, "Write a final summary to stderr")
	f.BoolVarP(&o.verbose, "verbose", "v", false, "Write individual outcomes to stderr")
	f.BoolVarP(&help, "help", "h", false, "Show help")
	f.BoolVar(&showVersion, "version", false, "Show version")
	if err := f.Parse(args); err != nil {
		return o, false, err
	}
	if help {
		_, err := fmt.Fprintf(stdout, "Usage: dnscheck [options]\n\nRead one domain or HTTP(S) URL per line from stdin or --input.\n\n%s", f.FlagUsages())
		return o, true, err
	}
	if showVersion {
		_, err := fmt.Fprintln(stdout, "dnscheck", buildVersion())
		return o, true, err
	}
	if f.NArg() != 0 {
		return o, false, errors.New("unexpected positional arguments; use --url or --input")
	}
	if o.target != "" && o.input != "" {
		return o, false, errors.New("--url and --input cannot be combined")
	}
	if f.Changed("url") && o.target == "" || f.Changed("input") && o.input == "" {
		return o, false, errors.New("input paths and target values must not be empty")
	}
	for _, name := range []string{"output", "dnsFile", "dnsServers", "confirm-resolvers"} {
		if f.Changed(name) && f.Lookup(name).Value.String() == "" {
			return o, false, fmt.Errorf("--%s must not be empty", name)
		}
	}
	if o.target != "" {
		name, err := normalizeInput(o.target)
		if err != nil {
			return o, false, fmt.Errorf("--url: %w", err)
		}
		if name == "" {
			return o, false, errors.New("--url must contain a domain or HTTP(S) URL")
		}
	}
	if appendOutput && o.overwrite {
		return o, false, errors.New("--append and --overwrite cannot be combined")
	}
	if (appendOutput || o.overwrite) && o.output == "" {
		return o, false, errors.New("--append and --overwrite require --output")
	}
	if !o.confirm && o.confirmResolvers != "" {
		return o, false, errors.New("--confirm-resolvers requires --confirm")
	}
	if o.workers < 1 || o.workers > 150 {
		return o, false, errors.New("--workers must be between 1 and 150")
	}
	if timeoutMS < 1 || timeoutMS > 10000 {
		return o, false, errors.New("--dns-timeout must be between 1 and 10000 milliseconds")
	}
	if o.attempts < 1 || o.attempts > 10 {
		return o, false, errors.New("--dns-retries must be between 1 and 10 attempts")
	}
	if o.errorLimit < 1 || o.cooldown <= 0 {
		return o, false, errors.New("--dns-errorLimit and --dns-cooldown must be positive")
	}
	if o.uniqueLimit < 1 || o.cacheSize < 0 || o.cacheSize > 1000000 || o.qps < 1 {
		return o, false, errors.New("--unique-limit and --rate-limit must be positive; --cache-size must be between 0 and 1000000")
	}
	o.timeout = time.Duration(timeoutMS) * time.Millisecond
	return o, false, nil
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		revision, dirty := "", ""
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				if setting.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
		if len(revision) > 12 {
			revision = revision[:12]
		}
		if revision != "" {
			return "dev-" + revision + dirty
		}
	}
	return "dev"
}
