package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testConfig(t *testing.T, args ...string) config {
	t.Helper()
	c, err := parseConfig(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testQuestions(t *testing.T, names ...string) []dns.Question {
	t.Helper()
	var questions []dns.Question
	for _, name := range names {
		q, err := makeQuestion(name, dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		questions = append(questions, q)
	}
	return questions
}

func startFixture(t *testing.T, network string, handler dns.HandlerFunc) string {
	t.Helper()
	server := &dns.Server{Handler: handler}
	var address string
	var err error
	if network == "udp" {
		server.PacketConn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err == nil {
			address = server.PacketConn.LocalAddr().String()
		}
	} else {
		server.Listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			address = server.Listener.Addr().String()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	server.NotifyStartedFunc = func() { close(started) }
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("fixture failed to start: %v", err)
	case <-time.After(time.Second):
		t.Fatal("fixture startup timeout")
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return address
}

func normalReply(w dns.ResponseWriter, q *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(q)
	switch q.Question[0].Name {
	case "missing.test.":
		r.Rcode = dns.RcodeNameError
	case "refused.test.":
		r.Rcode = dns.RcodeRefused
	case "truncated.test.":
		r.Truncated = true
	default:
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	}
	w.WriteMsg(r)
}

func TestConcurrentUDPAndTCPAccounting(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			address := startFixture(t, network, normalReply)
			c := testConfig(t, "-server", address, "-network", network, "-queries", "120", "-duration", "0", "-qps", "0", "-concurrency", "12")
			questions := testQuestions(t, "ok.test", "missing.test", "refused.test", "truncated.test")
			r := run(context.Background(), c, questions, map[int]bool{dns.RcodeSuccess: true, dns.RcodeNameError: true})
			if r.Attempted != 120 || r.Replies != 120 || r.UnexpectedRCodes != 30 || r.Truncated != 30 || r.Latency.Samples != 120 {
				t.Fatalf("unexpected accounting: %+v", r)
			}
			if r.RCodes["NOERROR"] != 60 || r.RCodes["NXDOMAIN"] != 30 || r.RCodes["REFUSED"] != 30 {
				t.Fatalf("unexpected rcodes: %v", r.RCodes)
			}
		})
	}
}

func TestConnectionsAreReused(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			var mu sync.Mutex
			clients := make(map[string]bool)
			address := startFixture(t, network, func(w dns.ResponseWriter, q *dns.Msg) {
				mu.Lock()
				clients[w.RemoteAddr().String()] = true
				mu.Unlock()
				normalReply(w, q)
			})
			c := testConfig(t, "-server", address, "-network", network, "-queries", "20", "-duration", "0", "-qps", "0", "-concurrency", "1")
			r := run(context.Background(), c, testQuestions(t, "ok.test"), map[int]bool{dns.RcodeSuccess: true})
			mu.Lock()
			defer mu.Unlock()
			if r.Replies != 20 || len(clients) != 1 {
				t.Fatalf("connections not reused: clients=%d report=%+v", len(clients), r)
			}
		})
	}
}

func TestTimeoutAndInvalidResponses(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, mode := range []string{"timeout", "question", "malformed"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				address := startFixture(t, network, func(w dns.ResponseWriter, q *dns.Msg) {
					switch mode {
					case "timeout":
						return
					case "question":
						r := new(dns.Msg)
						r.SetReply(q)
						r.Question[0].Name = "wrong.test."
						w.WriteMsg(r)
					case "malformed":
						w.Write([]byte{1, 2, 3})
					}
				})
				c := testConfig(t, "-server", address, "-network", network, "-queries", "2", "-duration", "0", "-qps", "0", "-concurrency", "1", "-timeout", "30ms")
				r := run(context.Background(), c, testQuestions(t, "ok.test"), map[int]bool{dns.RcodeSuccess: true})
				if r.Attempted != 2 || r.Replies != 0 || r.Latency.Samples != 0 {
					t.Fatalf("failed attempts included as replies: %+v", r)
				}
				if mode == "timeout" && r.Timeouts != 2 || mode != "timeout" && r.InvalidReplies != 2 {
					t.Fatalf("wrong error category: %+v", r)
				}
			})
		}
	}
}

func TestDurationDrainsAndInterruptCancels(t *testing.T) {
	t.Run("drain", func(t *testing.T) {
		address := startFixture(t, "udp", func(w dns.ResponseWriter, q *dns.Msg) {
			time.Sleep(80 * time.Millisecond)
			normalReply(w, q)
		})
		c := testConfig(t, "-server", address, "-duration", "40ms", "-queries", "1", "-qps", "0", "-concurrency", "1")
		r := run(context.Background(), c, testQuestions(t, "ok.test"), map[int]bool{dns.RcodeSuccess: true})
		if r.Replies != 1 || r.Timeouts != 0 || r.Interrupted || r.ElapsedSeconds < .08 {
			t.Fatalf("duration cancelled an in-flight reply: %+v", r)
		}
	})
	t.Run("interrupt", func(t *testing.T) {
		started := make(chan struct{}, 1)
		address := startFixture(t, "udp", func(w dns.ResponseWriter, q *dns.Msg) { started <- struct{}{} })
		c := testConfig(t, "-server", address, "-duration", "0", "-queries", "1", "-timeout", "10s", "-qps", "0", "-concurrency", "1")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan report, 1)
		go func() { done <- run(ctx, c, testQuestions(t, "ok.test"), map[int]bool{dns.RcodeSuccess: true}) }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("no query reached fixture")
		}
		cancel()
		select {
		case r := <-done:
			if !r.Interrupted || r.Cancelled != 1 || r.Timeouts != 0 {
				t.Fatalf("incorrect cancellation accounting: %+v", r)
			}
		case <-time.After(time.Second):
			t.Fatal("interrupt did not unblock socket read")
		}
	})
}

func TestQPSIsGlobal(t *testing.T) {
	address := startFixture(t, "udp", normalReply)
	c := testConfig(t, "-server", address, "-duration", "200ms", "-qps", "50", "-concurrency", "8")
	r := run(context.Background(), c, testQuestions(t, "ok.test"), map[int]bool{dns.RcodeSuccess: true})
	if r.Attempted < 2 || r.Attempted > 12 || r.Replies != r.Attempted {
		t.Fatalf("pacing is not a global bound: %+v", r)
	}
}

func TestConnectionFailureAndExitCodes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	var out, stderr bytes.Buffer
	code := execute(context.Background(), []string{"-server", address, "-network", "tcp", "-queries", "1", "-duration", "0", "-qps", "0", "-concurrency", "1", "-json"}, &out, &stderr)
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if code != 1 || r.IOErrors != 1 || r.Attempted != 1 {
		t.Fatalf("code=%d report=%+v", code, r)
	}
	out.Reset()
	if code := execute(context.Background(), []string{"-network", "https"}, &out, &stderr); code != 2 {
		t.Fatalf("invalid arguments exit=%d", code)
	}
	if code := execute(context.Background(), []string{"-help"}, &out, &stderr); code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	address = startFixture(t, "udp", normalReply)
	for _, tc := range []struct {
		expect string
		code   int
	}{{"NOERROR", 1}, {"REFUSED", 0}} {
		out.Reset()
		args := []string{"-server", address, "-name", "refused.test", "-queries", "1", "-qps", "0", "-concurrency", "1", "-expect-rcode", tc.expect}
		if code := execute(context.Background(), args, &out, &stderr); code != tc.code {
			t.Fatalf("expect=%s exit=%d: %s", tc.expect, code, stderr.String())
		}
	}
}

func TestConfigurationAndQuestionFile(t *testing.T) {
	for _, args := range [][]string{
		{"-server", "localhost:53"}, {"-server", "127.0.0.1:0"}, {"-network", "dot"},
		{"-concurrency", "0"}, {"-concurrency", "1025"}, {"-duration", "-1s"},
		{"-duration", "0"}, {"-timeout", "0"}, {"-qps", "-1"}, {"-edns-size", "511"},
		{"-edns-size", "65536"}, {"-edns-size", "0", "-dnssec"}, {"extra"},
	} {
		if _, err := parseConfig(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
	if _, err := parseRCodes("NOERROR,typo"); err == nil {
		t.Fatal("accepted unknown response code")
	}
	if _, err := makeQuestion(strings.Repeat("x", 64)+".test", dns.TypeA); err == nil {
		t.Fatal("accepted oversized DNS label")
	}
	for _, value := range []string{"BOGUS", "TYPE0", "TYPE65536"} {
		if _, err := parseType(value); err == nil {
			t.Fatalf("accepted invalid DNS type %s", value)
		}
	}
	path := filepath.Join(t.TempDir(), "queries.txt")
	if err := os.WriteFile(path, []byte("# mixed workload\nEXAMPLE.test AAAA # inline comment\nsecond.test\nprivate.test TYPE65280\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := testConfig(t, "-file", path, "-type", "TXT")
	questions, err := loadQuestions(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(questions) != 3 || questions[0].Name != "example.test." || questions[0].Qtype != dns.TypeAAAA || questions[1].Qtype != dns.TypeTXT || questions[2].Qtype != 65280 {
		t.Fatalf("incorrect question file: %v", questions)
	}
	for _, value := range []string{"# empty", "a.test A extra", "a.test TYPO", strings.Repeat("x", 70000)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadQuestions(c); err == nil {
			t.Fatalf("accepted invalid question file %q", value[:min(len(value), 40)])
		}
	}
}

func TestHistogramBoundsAndMerge(t *testing.T) {
	var h, other histogram
	if h.percentile(99) != 0 || h.summary().Samples != 0 {
		t.Fatal("empty histogram must report zero")
	}
	for i := 1; i <= 10000; i++ {
		d := time.Duration(i) * time.Microsecond
		if i%2 == 0 {
			h.add(d)
		} else {
			other.add(d)
		}
	}
	h.merge(&other)
	for _, percent := range []uint64{50, 95, 99} {
		want := time.Duration(percent*100) * time.Microsecond
		got := h.percentile(percent)
		if got < want || float64(got) > float64(want)*1.016 {
			t.Fatalf("p%d=%v outside upper-bound tolerance for %v", percent, got, want)
		}
	}
	s := h.summary()
	if s.Samples != 10000 || s.MinMS != .001 || s.MaxMS != 10 || s.MeanMS != 5.0005 {
		t.Fatalf("wrong histogram summary: %+v", s)
	}
}

func TestEDNSAndRDFlagsReachServer(t *testing.T) {
	var checked atomic.Uint64
	address := startFixture(t, "udp", func(w dns.ResponseWriter, q *dns.Msg) {
		if opt := q.IsEdns0(); opt != nil && opt.UDPSize() == 1400 && opt.Do() && !q.RecursionDesired {
			checked.Add(1)
		}
		normalReply(w, q)
	})
	c := testConfig(t, "-server", address, "-queries", "4", "-qps", "0", "-concurrency", "1", "-dnssec", "-edns-size", "1400", "-rd=false")
	r := run(context.Background(), c, testQuestions(t, "ok.test"), map[int]bool{dns.RcodeSuccess: true})
	if checked.Load() != 4 || r.Replies != 4 {
		t.Fatalf("EDNS/RD flags not sent: checked=%d report=%+v", checked.Load(), r)
	}
}
