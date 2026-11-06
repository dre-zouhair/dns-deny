package main

import (
	"log"

	"github.com/dre-zouhair/dns-deny/tests/integration/internal/mockdns"
	"github.com/miekg/dns"
)

func main() {
	errors := make(chan error, 4)
	for _, address := range []string{":53", ":5353"} {
		for _, network := range []string{"udp", "tcp"} {
			server := &dns.Server{Addr: address, Net: network, Handler: dns.HandlerFunc(mockdns.Handler)}
			go func() { errors <- server.ListenAndServe() }()
		}
	}
	log.Printf("mock upstream serving UDP/TCP ports 53 and 5353")
	log.Fatal(<-errors)
}
