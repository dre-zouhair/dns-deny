package mockdns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestReplyFixtures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		qt     uint16
		rcode  int
		answer string
	}{
		{"resolves-fine.test.", dns.TypeA, dns.RcodeSuccess, "93.184.216.34"},
		{"resolves-fine.test.", dns.TypeAAAA, dns.RcodeSuccess, "2001:db8::1"},
		{"sinkholed.test.", dns.TypeA, dns.RcodeSuccess, "0.0.0.0"},
		{"sinkholed6.test.", dns.TypeAAAA, dns.RcodeSuccess, "::"},
		{"malicious-ip.test.", dns.TypeA, dns.RcodeSuccess, "198.51.100.66"},
		{"sub.trie-blocked.test.", dns.TypeA, dns.RcodeSuccess, "203.0.113.60"},
		{"unknown.test.", dns.TypeA, dns.RcodeNameError, ""},
		{"servfail.test.", dns.TypeA, dns.RcodeServerFailure, ""},
	} {
		t.Run(tc.name+dns.TypeToString[tc.qt], func(t *testing.T) {
			q := new(dns.Msg)
			q.SetQuestion(tc.name, tc.qt)
			r := Reply(q, false)
			if r.Rcode != tc.rcode || r.Id != q.Id || !r.Response {
				t.Fatalf("invalid response: %s", r)
			}
			if tc.answer != "" {
				if len(r.Answer) != 1 || r.Answer[0].Header().Ttl != 300 {
					t.Fatalf("invalid answer: %s", r)
				}
				var value string
				switch rr := r.Answer[0].(type) {
				case *dns.A:
					value = rr.A.String()
				case *dns.AAAA:
					value = rr.AAAA.String()
				}
				if value != tc.answer {
					t.Fatalf("got %s, want %s", value, tc.answer)
				}
			}
		})
	}
}
func TestNegativeSOA(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("negative-soa.test.", dns.TypeA)
	r := Reply(q, false)
	if r.Rcode != dns.RcodeNameError || len(r.Ns) != 1 {
		t.Fatalf("missing negative SOA: %s", r)
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok || soa.Minttl != 30 || soa.Hdr.Ttl != 30 {
		t.Fatalf("incorrect negative TTL: %v", r.Ns)
	}
}
func TestLargeRepliesRespectTransportAndEDNS(t *testing.T) {
	for _, size := range []uint16{0, 512, 1232} {
		q := new(dns.Msg)
		q.SetQuestion("large-response.test.", dns.TypeTXT)
		if size != 0 {
			q.SetEdns0(size, false)
		}
		u := Reply(q, false)
		if !u.Truncated || len(u.Answer) != 0 || u.Len() > max(512, int(size)) {
			t.Fatalf("oversized UDP reply: %s", u)
		}
		r := Reply(q, true)
		if r.Truncated || len(r.Answer) != 20 {
			t.Fatalf("incomplete TCP reply: %s", r)
		}
	}
}
