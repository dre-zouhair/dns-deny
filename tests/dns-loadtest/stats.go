package main

import (
	"fmt"
	"math/bits"
	"time"

	"github.com/miekg/dns"
)

type latencyReport struct {
	Samples uint64  `json:"samples"`
	MinMS   float64 `json:"min_ms"`
	MeanMS  float64 `json:"mean_ms"`
	P50MS   float64 `json:"p50_upper_bound_ms"`
	P95MS   float64 `json:"p95_upper_bound_ms"`
	P99MS   float64 `json:"p99_upper_bound_ms"`
	MaxMS   float64 `json:"max_ms"`
}

type report struct {
	Server            string            `json:"server"`
	Network           string            `json:"network"`
	Concurrency       int               `json:"concurrency"`
	TargetQPS         int64             `json:"target_qps"`
	QueryLimit        uint64            `json:"query_limit"`
	DurationSeconds   float64           `json:"duration_seconds"`
	TimeoutSeconds    float64           `json:"timeout_seconds"`
	QuestionCount     int               `json:"question_count"`
	ElapsedSeconds    float64           `json:"elapsed_seconds"`
	Attempted         uint64            `json:"attempted"`
	Replies           uint64            `json:"replies"`
	Timeouts          uint64            `json:"timeouts"`
	IOErrors          uint64            `json:"io_errors"`
	InvalidReplies    uint64            `json:"invalid_replies"`
	Cancelled         uint64            `json:"cancelled"`
	UnexpectedRCodes  uint64            `json:"unexpected_rcodes"`
	Truncated         uint64            `json:"truncated"`
	AttemptsPerSecond float64           `json:"attempts_per_second"`
	RepliesPerSecond  float64           `json:"replies_per_second"`
	RCodes            map[string]uint64 `json:"rcodes"`
	Latency           latencyReport     `json:"latency"`
	Interrupted       bool              `json:"interrupted"`
}

// Sixty-four sub-buckets per power of two bound percentile overestimation
// below 1.563%, without retaining an unbounded sample slice during long runs.
type histogram struct {
	bins  [64 * 64]uint64
	count uint64
	sum   float64
	min   time.Duration
	max   time.Duration
}

func (h *histogram) add(d time.Duration) {
	if h.count == 0 || d < h.min {
		h.min = d
	}
	if d > h.max {
		h.max = d
	}
	h.count++
	h.sum += float64(d)
	ns := uint64(max(d, 1))
	exponent := bits.Len64(ns) - 1
	shift := max(exponent-6, 0)
	bucket := (ns - (uint64(1) << exponent)) >> shift
	h.bins[exponent*64+int(bucket)]++
}

func (h *histogram) merge(other *histogram) {
	if other.count == 0 {
		return
	}
	if h.count == 0 || other.min < h.min {
		h.min = other.min
	}
	h.max = max(h.max, other.max)
	h.count += other.count
	h.sum += other.sum
	for i, n := range other.bins {
		h.bins[i] += n
	}
}

func (h *histogram) percentile(percent uint64) time.Duration {
	if h.count == 0 {
		return 0
	}
	rank := h.count/100*percent + (h.count%100*percent+99)/100
	var seen uint64
	for i, n := range h.bins {
		seen += n
		if seen >= rank {
			exponent, offset := i/64, i%64
			shift := max(exponent-6, 0)
			upper := (uint64(1) << exponent) + (uint64(offset+1) << shift) - 1
			return min(time.Duration(upper), h.max)
		}
	}
	return h.max
}

func (h *histogram) summary() latencyReport {
	if h.count == 0 {
		return latencyReport{}
	}
	ms := float64(time.Millisecond)
	return latencyReport{
		Samples: h.count,
		MinMS:   float64(h.min) / ms,
		MeanMS:  h.sum / float64(h.count) / ms,
		P50MS:   float64(h.percentile(50)) / ms,
		P95MS:   float64(h.percentile(95)) / ms,
		P99MS:   float64(h.percentile(99)) / ms,
		MaxMS:   float64(h.max) / ms,
	}
}

type workerStats struct {
	attempted, replies, timeouts, ioErrors, invalid, cancelled, unexpected, truncated uint64
	rcodes                                                                            map[int]uint64
	latency                                                                           histogram
}

func summarize(c config, workers []workerStats, elapsed time.Duration, questionCount int, interrupted bool) report {
	r := report{
		Server: c.server, Network: c.network, Concurrency: c.concurrency, TargetQPS: c.qps,
		QueryLimit: c.queries, DurationSeconds: c.duration.Seconds(), TimeoutSeconds: c.timeout.Seconds(),
		QuestionCount: questionCount, ElapsedSeconds: elapsed.Seconds(), Interrupted: interrupted,
		RCodes: make(map[string]uint64),
	}
	var latency histogram
	for i := range workers {
		s := &workers[i]
		r.Attempted += s.attempted
		r.Replies += s.replies
		r.Timeouts += s.timeouts
		r.IOErrors += s.ioErrors
		r.InvalidReplies += s.invalid
		r.Cancelled += s.cancelled
		r.UnexpectedRCodes += s.unexpected
		r.Truncated += s.truncated
		for code, count := range s.rcodes {
			name, ok := dns.RcodeToString[code]
			if !ok {
				name = fmt.Sprintf("RCODE%d", code)
			}
			r.RCodes[name] += count
		}
		latency.merge(&s.latency)
	}
	r.Latency = latency.summary()
	if elapsed > 0 {
		r.AttemptsPerSecond = float64(r.Attempted) / elapsed.Seconds()
		r.RepliesPerSecond = float64(r.Replies) / elapsed.Seconds()
	}
	return r
}
