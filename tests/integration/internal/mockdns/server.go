package mockdns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func Reply(query *dns.Msg, tcp bool) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	if len(query.Question) != 1 {
		response.Rcode = dns.RcodeFormatError
		return response
	}
	q := query.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	var address string
	switch name {
	case "negative-soa.test":
		response.Rcode = dns.RcodeNameError
		response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 30}, Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 30}}
	case "large-response.test":
		if q.Qtype == dns.TypeTXT {
			for i := range 20 {
				response.Answer = append(response.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{fmt.Sprintf("%d-%s", i, strings.Repeat("x", 250))}})
			}
		}
	case "nxdomain.test":
		response.Rcode = dns.RcodeNameError
	case "servfail.test":
		response.Rcode = dns.RcodeServerFailure
	default:
		if q.Qtype == dns.TypeA {
			address = map[string]string{"resolves-fine.test": "93.184.216.34", "sinkholed.test": "0.0.0.0", "malicious-ip.test": "198.51.100.66", "sub.trie-blocked.test": "203.0.113.60"}[name]
		} else if q.Qtype == dns.TypeAAAA {
			address = map[string]string{"resolves-fine.test": "2001:db8::1", "sinkholed6.test": "::"}[name]
		}
		if address == "" {
			response.Rcode = dns.RcodeNameError
		} else {
			hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 300}
			if q.Qtype == dns.TypeA {
				response.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP(address).To4()}}
			} else {
				response.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(address)}}
			}
		}
	}
	if !tcp {
		limit := 512
		if opt := query.IsEdns0(); opt != nil {
			limit = max(512, int(opt.UDPSize()))
		}
		if response.Len() > limit {
			response.Truncated = true
			response.Answer, response.Ns, response.Extra = nil, nil, nil
		}
	}
	return response
}

func Handler(w dns.ResponseWriter, query *dns.Msg) {
	_, tcp := w.RemoteAddr().(*net.TCPAddr)
	if err := w.WriteMsg(Reply(query, tcp)); err != nil {
		log.Printf("mock response: %v", err)
	}
}
