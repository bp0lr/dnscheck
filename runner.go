package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type inputJob struct{ raw, domain string }

type inputSummary struct {
	lines, ignored, submitted int
	err                       error
}

type runStats struct {
	Lines      int            `json:"lines"`
	Ignored    int            `json:"ignored"`
	Submitted  int            `json:"submitted"`
	Completed  int            `json:"completed"`
	Outcomes   map[string]int `json:"outcomes"`
	Queries    uint64         `json:"queries"`
	CacheHits  uint64         `json:"cache_hits"`
	DurationMS int64          `json:"duration_ms"`
}

func feedInput(ctx context.Context, in io.Reader, o options, jobs chan<- inputJob, results chan<- result) inputSummary {
	var summary inputSummary
	var seen map[string]struct{}
	if o.unique {
		seen = make(map[string]struct{})
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), maxInputLine)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		summary.lines++
		raw := scanner.Text()
		name, err := normalizeInput(raw)
		if err == nil && name == "" {
			summary.ignored++
			continue
		}
		var immediate result
		if err != nil {
			immediate = result{Input: raw, Status: "invalid_input", Reason: "invalid_domain", Detail: err.Error()}
		} else if o.unique {
			if _, exists := seen[name]; exists {
				immediate = result{Input: raw, Domain: name, Status: "duplicate", Reason: "duplicate_input"}
			} else if len(seen) >= o.uniqueLimit {
				immediate = result{Input: raw, Domain: name, Status: "inconclusive", Reason: "unique_limit", Detail: "exact deduplication limit reached; remaining input was not read"}
				summary.err = errors.New("--unique-limit exceeded; remaining input was not read")
			} else {
				seen[name] = struct{}{}
			}
		}
		if immediate.Status != "" {
			select {
			case results <- immediate:
				summary.submitted++
			case <-ctx.Done():
				return summary
			}
			if summary.err != nil {
				return summary
			}
			continue
		}
		select {
		case jobs <- inputJob{raw, name}:
			summary.submitted++
		case <-ctx.Done():
			return summary
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		summary.err = fmt.Errorf("read input (lines must be shorter than %d bytes): %w", maxInputLine, err)
	}
	return summary
}

func writeResult(out io.Writer, o options, r result) error {
	if o.jsonl {
		return json.NewEncoder(out).Encode(r)
	}
	if r.Status != "valid" {
		return nil
	}
	if o.showIP {
		_, err := fmt.Fprintf(out, "%s : [A:%s] [AAAA:%s] [CNAME:%s]\n", r.Domain, strings.Join(r.Records.A, ","), strings.Join(r.Records.AAAA, ","), strings.Join(r.Records.CNAME, ","))
		return err
	}
	_, err := fmt.Fprintln(out, r.Domain)
	return err
}

func processInput(ctx context.Context, o options, in io.Reader, out, diagnostics io.Writer, check func(context.Context, string) result) (runStats, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Real input files and stdin can be closed to release a blocked scanner.
	stopRead := context.AfterFunc(ctx, func() {
		if closer, ok := in.(io.ReadCloser); ok {
			_ = closer.Close()
		}
	})
	defer stopRead()
	jobs := make(chan inputJob, o.workers)
	results := make(chan result, o.workers)
	inputDone := make(chan inputSummary, 1)
	var workers sync.WaitGroup
	for range o.workers {
		workers.Go(func() {
			for job := range jobs {
				r := result{Domain: job.domain, Status: "cancelled", Reason: "cancelled"}
				if ctx.Err() == nil {
					r = check(ctx, job.domain)
				}
				r.Input = job.raw
				// The collector always drains results, including after failure.
				results <- r
			}
		})
	}
	go func() {
		summary := feedInput(ctx, in, o, jobs, results)
		close(jobs)
		inputDone <- summary
	}()
	go func() { workers.Wait(); close(results) }()
	stats := runStats{Outcomes: make(map[string]int)}
	var outputErr error
	for r := range results {
		stats.Completed++
		stats.Outcomes[r.Status]++
		if outputErr != nil {
			continue
		}
		outputErr = writeResult(out, o, r)
		if outputErr == nil && o.verbose {
			_, outputErr = fmt.Fprintf(diagnostics, "%q: %s (%s) %s\n", r.Input, r.Status, r.Reason, r.Detail)
		}
		if outputErr != nil {
			cancel()
		}
	}
	summary := <-inputDone
	stats.Lines, stats.Ignored, stats.Submitted = summary.lines, summary.ignored, summary.submitted
	return stats, errors.Join(summary.err, outputErr, ctx.Err())
}

func protectOutput(path string, in io.Reader, stdout io.Writer, o options) error {
	destination, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, candidate := range []any{in, stdout} {
		if source, ok := candidate.(interface{ Stat() (os.FileInfo, error) }); ok {
			info, err := source.Stat()
			if err != nil {
				return err
			}
			if os.SameFile(info, destination) {
				return errors.New("output file must differ from the input and redirected stdout")
			}
		}
	}
	if o.resolverFile != "" && o.resolverList == "" {
		info, err := os.Stat(o.resolverFile)
		if err != nil {
			return err
		}
		if os.SameFile(info, destination) {
			return errors.New("output file must differ from the resolver file")
		}
	}
	return nil
}

func execute(ctx context.Context, o options, stdin io.Reader, stdout, stderr io.Writer) error {
	start := time.Now()
	servers, err := loadResolvers(o)
	if err != nil {
		return fmt.Errorf("load resolvers: %w", err)
	}
	var confirmation []string
	if o.confirmResolvers != "" {
		confirmation, err = parseResolverList(o.confirmResolvers)
		if err != nil {
			return fmt.Errorf("confirmation resolvers: %w", err)
		}
	}
	in := stdin
	if o.target != "" {
		in = strings.NewReader(o.target + "\n")
	}
	if o.input != "" {
		file, err := os.Open(o.input)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer file.Close()
		in = file
	}
	writers := []io.Writer{stdout}
	var outputFile *os.File
	if o.output != "" {
		if err := protectOutput(o.output, in, stdout, o); err != nil {
			return err
		}
		flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if o.overwrite {
			flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		}
		outputFile, err = os.OpenFile(o.output, flags, 0644)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		writers = append(writers, outputFile)
	}
	out := bufio.NewWriterSize(io.MultiWriter(writers...), 32*1024)
	checker := newDomainChecker(o, servers, confirmation)
	stats, workErr := processInput(ctx, o, in, out, stderr, checker.check)
	flushErr := out.Flush()
	var closeErr error
	if outputFile != nil {
		closeErr = outputFile.Close()
	}
	stats.Queries = checker.primary.transport.exchanges.Load()
	stats.CacheHits = checker.primary.transport.cacheHits.Load()
	stats.DurationMS = time.Since(start).Milliseconds()
	var statsErr error
	if o.showStats {
		if o.jsonl {
			statsErr = json.NewEncoder(stderr).Encode(struct {
				Stats runStats `json:"stats"`
			}{stats})
		} else {
			_, statsErr = fmt.Fprintf(stderr, "Lines: %d | Ignored: %d | Submitted: %d | Completed: %d\nValid: %d | NXDOMAIN: %d | NODATA: %d | Wildcard: %d | Inconclusive: %d | Invalid: %d | Duplicates: %d | Cancelled: %d\nQueries: %d | Cache hits: %d | Duration: %d ms\n",
				stats.Lines, stats.Ignored, stats.Submitted, stats.Completed,
				stats.Outcomes["valid"], stats.Outcomes["nxdomain"], stats.Outcomes["nodata"], stats.Outcomes["wildcard"], stats.Outcomes["inconclusive"], stats.Outcomes["invalid_input"], stats.Outcomes["duplicate"], stats.Outcomes["cancelled"], stats.Queries, stats.CacheHits, stats.DurationMS)
		}
	}
	var outcomeErr error
	if stats.Outcomes["inconclusive"]+stats.Outcomes["invalid_input"] > 0 {
		outcomeErr = fmt.Errorf("%d inconclusive and %d invalid inputs; use --jsonl or --verbose for individual reasons", stats.Outcomes["inconclusive"], stats.Outcomes["invalid_input"])
	}
	return errors.Join(workErr, flushErr, closeErr, statsErr, outcomeErr)
}
