package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type pacer struct {
	interval time.Duration
	start    time.Time
	next     atomic.Int64
}

func (p *pacer) wait(ctx context.Context, timer *time.Timer) bool {
	if ctx.Err() != nil {
		return false
	}
	if p.interval == 0 {
		return true
	}
	var slot int64
	for {
		previous := p.next.Load()
		// Discard accumulated pacing debt; outstanding reservations remain
		// bounded by concurrency rather than an unbounded work queue.
		slot = max(previous, time.Since(p.start).Nanoseconds())
		if p.next.CompareAndSwap(previous, slot+int64(p.interval)) {
			break
		}
	}
	delay := time.Until(p.start.Add(time.Duration(slot)))
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer.Reset(delay)
	select {
	case <-timer.C:
		return ctx.Err() == nil
	case <-ctx.Done():
		timer.Stop()
		return false
	}
}

func run(parent context.Context, c config, questions []dns.Question, expected map[int]bool) report {
	start := time.Now()
	issuance := parent
	if c.duration > 0 {
		var stop context.CancelFunc
		issuance, stop = context.WithTimeout(parent, c.duration)
		defer stop()
	}
	pacing := pacer{start: start}
	if c.qps > 0 {
		pacing.interval = time.Second / time.Duration(c.qps)
	}
	var sequence atomic.Uint64
	stats := make([]workerStats, c.concurrency)
	var workers sync.WaitGroup
	for i := range stats {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			work(parent, issuance, c, questions, expected, &pacing, &sequence, &stats[i])
		}(i)
	}
	workers.Wait()
	return summarize(c, stats, time.Since(start), len(questions), parent.Err() != nil)
}

func work(parent, issuance context.Context, c config, questions []dns.Question, expected map[int]bool,
	pacing *pacer, sequence *atomic.Uint64, stats *workerStats) {
	stats.rcodes = make(map[int]uint64)
	client := dns.Client{Net: c.network, Timeout: c.timeout, UDPSize: uint16(c.ednsSize)}
	message := dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: dns.Id(), RecursionDesired: c.rd},
		Question: make([]dns.Question, 1),
	}
	if c.ednsSize != 0 {
		message.SetEdns0(uint16(c.ednsSize), c.dnssec)
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var conn *dns.Conn
	var stopClosing func() bool
	closeConn := func() {
		if stopClosing != nil {
			stopClosing()
			stopClosing = nil
		}
		if conn != nil {
			conn.Close()
			conn = nil
		}
	}
	defer closeConn()
	for issuance.Err() == nil {
		index := sequence.Add(1) - 1
		if c.queries > 0 && index >= c.queries {
			return
		}
		if !pacing.wait(issuance, timer) {
			return
		}
		message.Id++
		message.Question[0] = questions[index%uint64(len(questions))]
		stats.attempted++
		started := time.Now()
		attempt, cancel := context.WithTimeout(parent, c.timeout)
		var err error
		if conn == nil {
			conn, err = client.DialContext(attempt, c.server)
			if err == nil {
				// The issuance deadline stops new work but lets replies drain.
				// A user interrupt instead closes sockets immediately.
				liveConn := conn
				stopClosing = context.AfterFunc(parent, func() { liveConn.Close() })
			}
		}
		var response *dns.Msg
		if err == nil {
			response, _, err = client.ExchangeWithConnContext(attempt, &message, conn)
		}
		elapsed := time.Since(started)
		cancel()
		if err != nil {
			switch {
			case parent.Err() != nil:
				stats.cancelled++
			case isTimeout(err):
				stats.timeouts++
			case errors.Is(err, dns.ErrId) || errors.Is(err, dns.ErrShortRead) || errors.Is(err, dns.ErrBuf):
				stats.invalid++
			default:
				var dnsError *dns.Error
				if errors.As(err, &dnsError) {
					stats.invalid++
				} else {
					stats.ioErrors++
				}
			}
			// A timed-out UDP socket may receive a late answer; a broken TCP
			// stream may contain a partial frame. Reconnect before retrying.
			closeConn()
			continue
		}
		if !validResponse(&message, response) {
			stats.invalid++
			closeConn()
			continue
		}
		stats.replies++
		stats.rcodes[response.Rcode]++
		if !expected[response.Rcode] {
			stats.unexpected++
		}
		if response.Truncated {
			stats.truncated++
		}
		stats.latency.add(elapsed)
	}
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout())
}

func validResponse(query, response *dns.Msg) bool {
	if response == nil || !response.Response || response.Id != query.Id || response.Opcode != dns.OpcodeQuery || len(response.Question) != 1 {
		return false
	}
	q, r := query.Question[0], response.Question[0]
	return q.Qtype == r.Qtype && q.Qclass == r.Qclass && strings.EqualFold(q.Name, r.Name)
}
