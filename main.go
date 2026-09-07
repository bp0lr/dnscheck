package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, handled, err := parseOptions(args, stdout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dnscheck: %v\n", err)
		if handled {
			return 1
		}
		return 2
	}
	if handled {
		return 0
	}
	if err := execute(ctx, o, stdin, stdout, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "dnscheck: %v\n", err)
		if ctx.Err() != nil {
			return 130
		}
		return 1
	}
	return 0
}
