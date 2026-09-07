# dnscheck

A small DNS checker written in Go. It reads domain names, checks A and CNAME records, and filters results using wildcard detection and a second DNS lookup.

Originally built to clean lists of subdomains, dnscheck uses resolver components from [dmut](https://github.com/bp0lr/dmut).

Use it as a command-line filter for an existing domain list. Results describe DNS answers; they do not establish HTTP availability or service health.

The project is being modernized. See the [improvement roadmap](ROADMAP.md) for the planned commits and their acceptance criteria. This README describes the current implementation.

## Requirements

- Go 1.26.0 or newer to build from source. Use the latest patch release of a supported Go version.
- Network access to the configured DNS resolvers and to `8.8.8.8:53`, which the current implementation uses for wildcard checks and confirmation.

## Build

From a checkout of this repository:

```sh
go build -o dnscheck .
./dnscheck --help
```

On Windows, use `go build -o dnscheck.exe .` and run `./dnscheck.exe`.

## Usage

Check a single domain:

```sh
./dnscheck -u example.com
```

Read one domain per line from a file:

```sh
./dnscheck < domains.txt
```

In PowerShell:

```powershell
Get-Content domains.txt | ./dnscheck.exe
```

Use a resolver file and append matching domains to an output file:

```sh
./dnscheck --dnsFile resolvers.txt -w 50 -o results.txt < domains.txt
```

The resolver file accepts one IPv4 resolver per line, with an optional port. For example:

```text
1.1.1.1:53
9.9.9.9:53
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-u, --url` | stdin | Check one domain name. |
| `-w, --workers` | `25` | Concurrent workers, from 1 to 150. |
| `-o, --output` | none | Append results to a file. |
| `-s, --dnsFile` | none | Read DNS resolvers from a file. |
| `-l, --dnsServers` | none | Comma-separated resolvers; overrides `--dnsFile`. |
| `--dns-timeout` | `500` | Timeout in milliseconds for regular DNS queries. |
| `--dns-retries` | `3` | Query attempts in the current resolver implementation. |
| `--dns-errorLimit` | `25` | Error threshold used to disable a resolver. |
| `--show-ip` | `false` | Include returned A and CNAME values. |
| `--show-stats` | `false` | Print the current statistics summary. See limitations below. |
| `-v, --verbose` | `false` | Print diagnostic messages. |
| `-h, --help` | | Show command help. |

Without explicit resolvers, dnscheck looks for `~/.dmut/resolvers.txt`, then falls back to built-in Cloudflare, Google, and Quad9 resolvers.

## Current limitations

- Supply domain names, not full URLs. Input validation still needs improvement.
- Only A and CNAME queries are used; AAAA-only domains are not supported.
- Wildcard checks and confirmation use Google DNS even when custom resolvers are configured. Confirmation also uses fixed timeout and retry values.
- Wildcard filtering is heuristic and can discard valid domains. A matching result does not establish that a website is reachable.
- Statistics are not reliable yet: the total counter is not updated and worker counters are not synchronized.
- Verbose messages and statistics are written to stdout alongside results.
- Output files are appended to, and duplicate input domains may produce duplicate results.
- `--help` currently prints usage and exits with status 2. Other operational failures may incorrectly exit with status 0.

## Planned improvements

The [roadmap](ROADMAP.md) prioritizes input validation, resolver reliability, more accurate DNS classification, AAAA support, JSONL output, and measured performance improvements. These are planned features and are not available yet.

## Development

```sh
go test ./...
go vet ./...
```

There are currently no automated test cases. A successful `go test` checks that the package compiles; it does not validate DNS behavior.

## Reporting a problem

Include the command, Go version, operating system, resolver configuration, and expected versus actual output. Prefer a minimal synthetic example and remove private domain names and sensitive output before sharing it. Until `--version` is implemented, include the commit from `git rev-parse --short HEAD`.
