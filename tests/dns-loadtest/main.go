package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

type config struct {
	server      string
	network     string
	concurrency int
	duration    time.Duration
	queries     uint64
	qps         int64
	timeout     time.Duration
	name        string
	qtype       string
	file        string
	ednsSize    uint
	dnssec      bool
	rd          bool
	expect      string
	json        bool
}

func parseConfig(args []string, output io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("dns-loadtest", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&c.server, "server", "127.0.0.1:1053", "DNS server literal IP:port (bracket IPv6)")
	fs.StringVar(&c.network, "network", "udp", "Transport: udp or tcp; UDP never retries over TCP")
	fs.IntVar(&c.concurrency, "concurrency", 32, "Concurrent workers/connections (1-1024)")
	fs.DurationVar(&c.duration, "duration", 30*time.Second, "Stop issuing after this duration; 0 requires -queries")
	fs.Uint64Var(&c.queries, "queries", 0, "Maximum query attempts; 0 runs until duration or interrupt")
	fs.Int64Var(&c.qps, "qps", 1000, "Global target queries/second; 0 is unlimited")
	fs.DurationVar(&c.timeout, "timeout", time.Second, "Per-attempt deadline, including connection setup")
	fs.StringVar(&c.name, "name", "example.com", "Name to query when -file is absent")
	fs.StringVar(&c.qtype, "type", "A", "Default DNS type, e.g. A, AAAA, TXT, or TYPE65280")
	fs.StringVar(&c.file, "file", "", "Query file: one name [type] per line; # starts a comment")
	fs.UintVar(&c.ednsSize, "edns-size", 1232, "Advertised UDP payload size (512-65535); 0 disables EDNS")
	fs.BoolVar(&c.dnssec, "dnssec", false, "Set the EDNS DNSSEC OK bit; requires EDNS")
	fs.BoolVar(&c.rd, "rd", true, "Set recursion desired")
	fs.StringVar(&c.expect, "expect-rcode", "NOERROR,NXDOMAIN", "Comma-separated acceptable DNS response codes")
	fs.BoolVar(&c.json, "json", false, "Write the final report as JSON")
	fs.Usage = func() {
		fmt.Fprintln(output, "Usage: dns-loadtest [options]\n\nConcurrent DNS load generator. Reuses one connection per worker.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	return c, c.validate()
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c, err := parseConfig(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "dns-loadtest:", err)
		return 2
	}
	questions, err := loadQuestions(c)
	if err != nil {
		fmt.Fprintln(stderr, "dns-loadtest:", err)
		return 2
	}
	expected, err := parseRCodes(c.expect)
	if err != nil {
		fmt.Fprintln(stderr, "dns-loadtest:", err)
		return 2
	}
	fmt.Fprintf(stderr, "Testing %s over %s with %d workers, %d question(s), target %d QPS (0 = unlimited)\n",
		c.server, c.network, c.concurrency, len(questions), c.qps)
	report := run(ctx, c, questions, expected)
	if c.json {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(report)
	} else {
		err = printReport(stdout, report)
	}
	if err != nil {
		fmt.Fprintln(stderr, "dns-loadtest: writing report:", err)
		return 2
	}
	if report.Interrupted {
		return 130
	}
	if report.Attempted == 0 || report.Replies != report.Attempted || report.UnexpectedRCodes != 0 {
		return 1
	}
	return 0
}

func printReport(w io.Writer, r report) error {
	_, err := fmt.Fprintf(w, "\nServer: %s (%s)\nElapsed: %.3fs (includes draining in-flight attempts)\nAttempts: %d  Replies: %d  Unexpected RCODEs: %d\nTimeouts: %d  I/O errors: %d  Invalid replies: %d  Cancelled: %d\nAttempt rate: %.1f/s  Reply rate: %.1f/s\nTruncated replies: %d\nLatency of valid replies (ms): min %.3f  mean %.3f  p50 <= %.3f  p95 <= %.3f  p99 <= %.3f  max %.3f\n",
		r.Server, r.Network, r.ElapsedSeconds, r.Attempted, r.Replies, r.UnexpectedRCodes,
		r.Timeouts, r.IOErrors, r.InvalidReplies, r.Cancelled, r.AttemptsPerSecond, r.RepliesPerSecond,
		r.Truncated, r.Latency.MinMS, r.Latency.MeanMS, r.Latency.P50MS, r.Latency.P95MS, r.Latency.P99MS, r.Latency.MaxMS)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(r.RCodes))
	for key := range r.RCodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err = fmt.Fprintf(w, "  %s: %d\n", key, r.RCodes[key]); err != nil {
			return err
		}
	}
	if r.Interrupted {
		_, err = fmt.Fprintln(w, "Interrupted; partial results shown.")
	}
	return err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
