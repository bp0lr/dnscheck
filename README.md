# dnscheck

A small DNS filter for existing domain lists, written in Go. Check A, AAAA and CNAME records, identify wildcard matches, and retain the reason behind each result.

- Read domains or HTTP(S) URLs from stdin, a file, or a single argument.
- Use your own IPv4 or IPv6 resolvers throughout resolution, wildcard checks and confirmation.
- Output matching domains for pipelines, or JSONL with positive, negative and inconclusive outcomes.
- Bound concurrency, DNS query rate, cached replies and optional deduplication.

Originally built using components from [dmut](https://github.com/bp0lr/dmut), dnscheck now uses [miekg/dns](https://github.com/miekg/dns) directly.

## Requirements and installation

Building requires Go 1.26.0 or newer. Use the latest patch release of a supported Go version.

```sh
go install github.com/bp0lr/dnscheck@latest
dnscheck --help
```

Or build from a checkout:

```sh
go build -o dnscheck .
./dnscheck --version
```

On Windows, use `go build -o dnscheck.exe .` and run `./dnscheck.exe`. CI builds binaries for Linux, macOS and Windows and attaches them to successful workflow runs.

## Usage

Check a single domain or URL:

```sh
dnscheck -u example.com
dnscheck -u https://example.com/path
```

Read a file, omit repeated normalized domains, and write matching results:

```sh
dnscheck --input domains.txt --unique --show-stats -o results.txt
```

Read stdin in Bash or PowerShell:

```sh
dnscheck < domains.txt
```

```powershell
Get-Content domains.txt | ./dnscheck.exe
```

Use custom resolvers and save all outcomes as JSONL:

```sh
dnscheck --input domains.txt --dnsFile resolvers.txt --jsonl --show-stats -o results.jsonl --overwrite
```

Input supports blank lines, full-line `#` comments, CRLF, internationalized names and a trailing root dot. Names are normalized to lowercase ASCII. URL credentials, IP literals and malformed hostnames are rejected. Internal single-label names are accepted; configure an appropriate internal resolver for them. Input lines must be shorter than 64 KiB.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-u, --url` | none | Check one domain or HTTP(S) URL. |
| `--input` | stdin | Read a file; cannot be combined with `--url`. |
| `-w, --workers` | `25` | Concurrent workers, from 1 to 150. |
| `-o, --output` | none | Write results to a file as well as stdout. |
| `--append` | append behavior | Explicitly append to the output file. |
| `--overwrite` | `false` | Replace the output file; incompatible with `--append`. |
| `-s, --dnsFile` | none | Read resolver IP addresses from a file. |
| `-l, --dnsServers` | none | Comma-separated resolver IPs; overrides `--dnsFile`. |
| `--dns-timeout` | `500` | Timeout per network exchange in milliseconds, from 1 to 10000. |
| `--dns-retries` | `3` | Total query attempts, from 1 to 10, including the first attempt. |
| `--dns-errorLimit` | `25` | Consecutive failures before a resolver enters cooldown. |
| `--dns-cooldown` | `30s` | Duration before a failed resolver becomes eligible again. |
| `--confirm` | `true` | Confirm positive results with a fresh lookup. |
| `--confirm-resolvers` | normal pool | Comma-separated resolver IPs for confirmation. |
| `--wildcard` | `true` | Compare positive results with wildcard control names. |
| `--rate-limit` | `100` | Maximum DNS network exchanges per second across all workers and stages. |
| `--cache-size` | `4096` | Maximum cached replies; `0` disables caching. |
| `--unique` | `false` | Process each normalized name once. |
| `--unique-limit` | `100000` | Maximum retained unique names; exceeding it stops input with an error. |
| `--jsonl` | `false` | Write every processed outcome as a JSON object on its own line. |
| `--show-ip` | `false` | Include A, AAAA and CNAME values in plain output. |
| `--show-stats` | `false` | Write final counts, queries, cache hits and duration to stderr. |
| `-v, --verbose` | `false` | Write individual outcomes and reasons to stderr. |
| `--version` | | Show the version or development revision and exit successfully. |
| `-h, --help` | | Show help and exit successfully. |

Boolean options can be disabled explicitly, for example `--confirm=false` or `--wildcard=false`.

## Resolvers and classification

A resolver file accepts one IP address per line, with an optional port. Blank lines and full-line comments are ignored. Use brackets when specifying a port for IPv6:

```text
1.1.1.1:53
9.9.9.9
[2001:db8::53]:5353
```

The IPv6 address above is a documentation example. Without explicit resolvers, dnscheck reads `~/.dmut/resolvers.txt` if it exists, then falls back to Cloudflare, Google and Quad9. An unreadable, invalid or empty resolver file produces an error. No wildcard or confirmation stage silently switches to Google DNS.

Related record queries and wildcard controls use the same resolver. Confirmation prefers another resolver from the configured pool; with only one resolver it repeats the lookup there. Set `--confirm-resolvers` to choose a separate confirmation pool. Confirmation requires relevant records, not just `NOERROR`. Different address values are allowed because legitimate DNS answers can change across resolvers.

Wildcard checks compare two random sibling names with the candidate's records. Matching controls produce a `wildcard` outcome. Stable controls with different records preserve an explicit candidate; varying controls and failed checks produce an `inconclusive` outcome. Registrable roots and single-label names are not checked with sibling controls.

Wildcard detection is a heuristic. It cannot reliably distinguish an explicit record from a wildcard returning identical records, and changing or name-dependent answers can remain inconclusive. DNS results do not establish HTTP availability, service health or DNSSEC validation. A CNAME-only match can exist even when its target has no address records.

## Output and exit codes

Plain output contains only matching domains. `--show-ip` uses the same format on stdout and in the output file:

```text
example.test : [A:192.0.2.1] [AAAA:2001:db8::1] [CNAME:]
```

JSONL includes the original input, normalized domain, status, reason, records, resolver information and whether confirmation and wildcard checks ran. For example:

```json
{"input":"absent.test","domain":"absent.test","status":"nxdomain","reason":"name_does_not_exist","resolver":"127.0.0.1:5353","records":{},"confirmed":false,"wildcard_checked":false}
```

| Status | Meaning |
| --- | --- |
| `valid` | Relevant DNS records were found and enabled checks passed. |
| `nxdomain` | The resolver reported that the name does not exist. |
| `nodata` | Successful replies contained no A, AAAA or CNAME records for the name. |
| `wildcard` | Candidate records matched both wildcard controls. |
| `inconclusive` | A query failed, replies disagreed, controls varied, or the deduplication limit was reached. |
| `invalid_input` | The input could not be normalized into a supported domain name. |
| `duplicate` | `--unique` already admitted this normalized name. |
| `cancelled` | Admitted work was interrupted. |

Results arrive in completion order. JSONL includes invalid and duplicate inputs; blank lines and comments have no result record. Diagnostics and summaries go to stderr. With JSONL, the summary is a separate JSON object under a `stats` key on stderr; operational errors may also write text there.

The summary distinguishes scanned lines, ignored lines, admitted work (`submitted`) and completed outcomes. Admitted work is drained on cancellation; unread input is not counted. Partial results are flushed when possible. The output file is appended to by default, and empty files are retained. Using the same file for input and output is rejected.

| Exit code | Meaning |
| --- | --- |
| `0` | Completed successfully, including runs with only negative DNS results. |
| `1` | Operational error, invalid input lines or inconclusive results. Partial output may exist. |
| `2` | Invalid CLI usage or option values. |
| `130` | Interrupted or cancelled. |

## Performance and testing

Processing streams input through bounded worker queues and a buffered result writer. DNS replies are cached per resolver, name and record type, with TTL expiry and bounded LRU eviction. Negative answers require an applicable SOA; transient failures are not cached. Confirmation and wildcard controls always bypass the cache. Exact deduplication is optional and stops clearly when its configured capacity is exceeded.

Run the tests and static checks:

```sh
go test ./...
go vet ./...
go test -race ./...
```

Tests use synthetic DNS servers on loopback, covering TCP fallback, cancellation, IPv6, wildcard cases, confirmation, input errors, output files and cache behavior. The race detector requires a supported C toolchain. CI runs tests on Linux, macOS and Windows with Go 1.26 and 1.27, and runs the race detector on Linux.

Reproduce the repeated-query microbenchmark:

```sh
go test -run '^$' -bench '^BenchmarkRepeatedDNS$' -benchtime=1000x -benchmem
```

On Windows amd64 with Go 1.26.8, 1,000 sequential identical resolver queries used 1,000 network exchanges without caching and 1 exchange with caching. Allocations fell from 66 to 6 per operation in that run. This isolates repeated lookups within the TTL; it does not measure full application throughput or predict gains for unique names, wildcard checks or confirmation.

## Reporting a problem

Include `dnscheck --version`, the command, operating system, resolver configuration, and expected versus actual output. Prefer a small synthetic example and remove private names or sensitive URL data before sharing results.
