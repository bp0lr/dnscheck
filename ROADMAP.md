# dnscheck improvement plan

## Goal

Make dnscheck a dependable, small command-line filter for supplied domain lists. Prioritize correct classification, clear output, and predictable resource use.

The target is a subjective usefulness rating of 7 or 8 out of 10 after validation. Adding flags alone does not meet that target. The acceptance criteria below provide evidence for a new assessment.

## Baseline

- The existing application checks A and CNAME records using components from dmut.
- Compilation and `go vet` passed with Go 1.26.8 on Windows. No automated test cases exist yet.
- Input parsing, shared counters, resolver errors, wildcard classification, and fixed confirmation settings need correction.
- There is no measured performance baseline. No speedup is claimed.
- Go 1.26.0 is the minimum in the prepared changes. Its module changes and this documentation are recorded in separate commits.

## Commit sequence

Numbers below identify planned implementation stages. Deliver each stage as a separate commit, splitting it further when needed to keep changes focused. Each implementation commit must update help text and README examples for the behavior it actually adds.

| Plan ID | Proposed commit title | Depends on | Size |
| --- | --- | --- | --- |
| 01 | Raise the minimum Go version to 1.26.0 | Current main | Small |
| 02 | Document current behavior and the improvement roadmap | 01 | Small |
| 03 | Validate CLI input and establish automated checks | 01 | Medium |
| 04 | Isolate resolver state and make execution reliable | 03 | Medium |
| 05 | Correct DNS classification and add IPv6 record support | 04 | Medium |
| 06 | Add structured results and explicit output controls | 05 | Medium |
| 07 | Reduce repeated work with measured, bounded optimizations | 06 | Medium |
| 08 | Prepare reproducible releases and project presentation | 07 | Small |

Stages 01 and 02 are recorded in commits `5181f93` and `d371b2d`. Stages 03 through 08 are planned work, not implemented features. Keep each commit independently reviewable and validate it before continuing. This project uses separate commits for these improvements; pull requests are not part of the delivery workflow.

### 01: Supported Go baseline

- Set `go 1.26.0` and synchronize the module graph with `go mod tidy`.
- Preserve existing dependency versions in this commit so compatibility changes remain easy to review.
- Validate compilation and static analysis with Go 1.26.8.

Acceptance: `go test -mod=readonly ./...`, `go vet -mod=readonly ./...`, and `git diff --check` pass. Record that the test command currently checks compilation only. Full dependency modernization belongs to stage 04.

### 02: Accurate documentation and roadmap

- Explain the current purpose, build requirements, resolver precedence, and output behavior.
- Include examples for Bash and PowerShell and a complete current options table.
- Document current correctness limitations and link this plan.
- Keep planned flags out of the current usage section and avoid unmeasured performance claims.

Acceptance: examples and defaults match the source, relative links resolve, and no planned feature is presented as available. Use plain English without em dashes.

### 03: CLI and input reliability

- Extract a testable command runner with explicit configuration and input/output streams.
- Add `--input` and `--version`; return success for `--help` and `--version`.
- Normalize whitespace, blank lines, full-line comments, case, trailing dots, and URL hostnames. Handle CRLF and internationalized names explicitly.
- Reject malformed names and invalid numeric options without panics. Define the policy for IP literals and internal single-label names.
- Validate resolver addresses with proper IPv4/IPv6 host and port handling.
- Propagate file and scanner errors. Define exit codes: 0 for a completed run, 1 for an operational failure, and 2 for invalid command usage. A negative DNS answer is a completed result, not a CLI failure.
- Introduce unit tests and CI using supported Go versions. Keep test input local and synthetic.

Acceptance: table-driven tests cover malformed input, URL host extraction, CRLF, invalid flags, missing files, and help/version exit codes. Existing flag names continue to work. CI runs tests and vet; run the race detector on a supported runner.

### 04: Resolver and execution reliability

- Replace the dmut resolver dependency with a small adapter around miekg/dns. Audit and update the remaining dependency versions in this stage.
- Return actual errors and remove process exits from resolver internals.
- Own resolver health state explicitly and synchronize concurrent access. Recover resolvers after transient failures using a defined cooldown policy.
- Apply configured timeouts and attempt limits consistently. Preserve UDP-to-TCP fallback for truncated responses.
- Use a single result collector for counters and buffered output. Propagate write, flush, and close errors.
- Add context cancellation and Ctrl+C handling that stops new work and flushes completed results.

Acceptance: deterministic local DNS tests exercise timeout, exhausted resolvers, TCP fallback failure, and cancellation. Concurrent tests pass `go test -race`; counters reconcile with submitted work. Tests prove writes and flush failures are reported. CI also builds for Linux, macOS, and Windows.

### 05: Accurate DNS recognition

- Add AAAA support while keeping A and CNAME behavior explicit.
- Distinguish positive answers, NXDOMAIN, NOERROR with no requested data, wildcard matches, invalid input, and inconclusive outcomes such as timeouts or SERVFAIL.
- Use only configured resolvers for normal resolution and explicitly configured confirmation resolvers for confirmation. Remove hidden dependence on Google DNS.
- Require relevant answer data for confirmation; NOERROR alone is insufficient. Document the policy for disagreements between resolvers and for internal DNS.
- Rework wildcard classification with a local fixture suite, including explicit records beneath wildcard zones, nested zones, and changing answer sets. Uncertainty must remain visible instead of silently discarding a domain.
- Define whether a CNAME-only answer counts as a match and distinguish it from a confirmed address record.

Acceptance: a versioned local DNS fixture suite has expected classifications for A-only, AAAA-only, CNAME-only, empty answers, negative answers, wildcard cases, resolver disagreements, and transient failures. The suite reports false positive and false negative counts. These controlled results do not imply universal real-world accuracy.

### 06: Useful output and small usability additions

- Keep plain domain output as the default; move diagnostics and summaries to stderr.
- Add `--jsonl` with one record per processed input and a documented schema: input, normalized domain, outcome, records, resolver, and failure or discard reason when applicable.
- Add a summary of outcomes and duration, including skipped and cancelled work with clearly defined counting rules.
- Add explicit `--append` and `--overwrite` modes. Preserve the current append default for compatibility and reject conflicting modes.
- Make `--show-ip` formatting consistent between terminal and file output.

Acceptance: golden output tests verify valid JSONL, stream separation, reason codes, compatibility of default plain output, and output-file behavior. Include duplicate inputs and partial operational failures. README examples are copied from actual verified output.

### 07: Measured performance improvements

- First record local baseline benchmarks for unique inputs, repeated inputs, shared DNS ancestry, slow replies, and failing resolvers.
- Measure queries per input, elapsed time, allocations, and peak memory using the same fixtures and concurrency settings before and after changes.
- Add optional `--unique`, with a documented memory budget. Fail clearly if an exact deduplication budget is exhausted; do not silently drop inputs using probabilistic matches.
- Evaluate bounded result caching keyed by normalized name, record type, and resolver policy. Respect TTL and negative-answer semantics; do not cache transient failures as nonexistent domains.
- Coalesce equivalent in-flight work only where classification and resolver isolation remain correct.
- Avoid unnecessary response-to-text conversion. Add a configured query-rate limit and bounded queues for predictable resource use.
- Keep only optimizations that improve measured behavior without changing expected classifications.

Acceptance: include reproducible benchmark commands and before/after results in a versioned benchmark report alongside the changes. All classification fixtures still pass, cache bounds are tested, and cancellation and slow output do not leak goroutines. Do not claim a percentage speedup before measuring it.

### 08: Distribution and presentation

- Build versioned binaries for Linux, macOS, and Windows, with checksums and version metadata.
- Use a single release workflow tied to tags and document how artifacts are produced.
- Refresh the README with verified examples, compatibility notes, measured results, and a short migration guide.
- Prepare a clear repository description, relevant topics, and contribution/bug-report guidance using synthetic reproducible cases.
- Add CI and release badges only when the corresponding workflows and releases exist.
- Preserve attribution to dmut. Repository licensing requires the owner's explicit choice before adding a license.

Acceptance: release artifacts pass an offline help/version smoke check, checksums match, installation instructions match available artifacts, and documentation has no dead links or unsupported claims. Publishing a release is a separate final action after reviewing the artifacts.

## What would justify a 7 or 8?

- **Reliable results:** regression cases cover the known misclassifications and expose inconclusive answers.
- **Trustworthy automation:** exit codes, stream separation, JSONL, counters, and file errors behave consistently.
- **Practical coverage:** IPv6 records, file input, URL normalization, and resolver configuration work as documented.
- **Predictable cost:** cancellation, concurrency, queue, cache, and query-rate limits are tested; performance claims have measurements.
- **Maintainability:** supported Go versions, dependency checks, CI, reproducible binaries, and documentation stay aligned.

A 7 is a reasonable target once the correctness and usability criteria pass. An 8 would also need measured performance and successful use on representative owner-supplied workloads. Reassess after implementation; the score is not a product guarantee.
