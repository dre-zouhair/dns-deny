package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func (c config) validate() error {
	address, err := netip.ParseAddrPort(c.server)
	if err != nil || address.Port() == 0 {
		return fmt.Errorf("-server must be a literal IP:port with a nonzero port, e.g. 127.0.0.1:1053 or [::1]:1053")
	}
	if c.network != "udp" && c.network != "tcp" {
		return fmt.Errorf("-network must be udp or tcp")
	}
	if c.concurrency < 1 || c.concurrency > 1024 {
		return fmt.Errorf("-concurrency must be between 1 and 1024")
	}
	if c.duration < 0 || (c.duration == 0 && c.queries == 0) {
		return fmt.Errorf("use a positive -duration or a nonzero -queries limit")
	}
	if c.timeout <= 0 {
		return fmt.Errorf("-timeout must be positive")
	}
	if c.qps < 0 || c.qps > 1_000_000_000 {
		return fmt.Errorf("-qps must be between 0 (unlimited) and 1000000000")
	}
	if c.ednsSize != 0 && (c.ednsSize < 512 || c.ednsSize > 65535) {
		return fmt.Errorf("-edns-size must be 0 or between 512 and 65535")
	}
	if c.dnssec && c.ednsSize == 0 {
		return fmt.Errorf("-dnssec requires a nonzero -edns-size")
	}
	return nil
}

func parseType(value string) (uint16, error) {
	value = strings.ToUpper(value)
	if qt, ok := dns.StringToType[value]; ok && qt != 0 {
		return qt, nil
	}
	if strings.HasPrefix(value, "TYPE") {
		if n, err := strconv.ParseUint(value[4:], 10, 16); err == nil && n != 0 {
			return uint16(n), nil
		}
	}
	return 0, fmt.Errorf("unknown DNS type %q", value)
}

func makeQuestion(name string, qt uint16) (dns.Question, error) {
	name = dns.Fqdn(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return dns.Question{}, fmt.Errorf("invalid DNS name %q", name)
	}
	question := dns.Question{Name: dns.CanonicalName(name), Qtype: qt, Qclass: dns.ClassINET}
	// Packing catches invalid escapes and wire-length errors that the name
	// syntax check alone does not reject.
	if _, err := (&dns.Msg{Question: []dns.Question{question}}).Pack(); err != nil {
		return dns.Question{}, fmt.Errorf("invalid DNS name %q: %w", name, err)
	}
	return question, nil
}

func loadQuestions(c config) ([]dns.Question, error) {
	qt, err := parseType(c.qtype)
	if err != nil {
		return nil, err
	}
	if c.file == "" {
		question, err := makeQuestion(c.name, qt)
		if err != nil {
			return nil, err
		}
		return []dns.Question{question}, nil
	}
	file, err := os.Open(c.file)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var questions []dns.Question
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 2 {
			return nil, fmt.Errorf("%s:%d: expected name [type]", c.file, line)
		}
		lineType := qt
		if len(fields) == 2 {
			lineType, err = parseType(fields[1])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", c.file, line, err)
			}
		}
		question, err := makeQuestion(fields[0], lineType)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", c.file, line, err)
		}
		questions = append(questions, question)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", c.file, err)
	}
	if len(questions) == 0 {
		return nil, fmt.Errorf("%s contains no questions", c.file)
	}
	return questions, nil
}

func parseRCodes(value string) (map[int]bool, error) {
	codes := make(map[int]bool)
	for _, name := range strings.Split(value, ",") {
		name = strings.ToUpper(strings.TrimSpace(name))
		code, ok := dns.StringToRcode[name]
		if !ok {
			return nil, fmt.Errorf("unknown response code %q in -expect-rcode", name)
		}
		codes[code] = true
	}
	return codes, nil
}
