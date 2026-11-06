package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func bytesContain(data []byte, text string) bool { return strings.Contains(string(data), text) }

func resolutionCases() []testCase {
	return []testCase{
		{"test_authorized_dns_client_and_unauthenticated_admin_client", func(c *caseEnv) {
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			client := *c.s.api
			client.key = ""
			r, err := client.call(context.Background(), "GET", "/config", nil)
			if err != nil {
				c.Fatal(err)
			}
			c.check(r.status == 401 || r.status == 403, "unauthenticated config allowed: %d", r.status)
		}},
		{"test_custom_upstream_port_is_explicitly_restart_scoped", func(c *caseEnv) {
			c.restore("/config/upstreams")
			r := jsonAs[M](c, c.post("/config/upstreams", M{"upstreams": []M{{"address": "192.0.2.53:5353", "protocol": "udp", "tls_sni": nil, "doh_path": nil}}}))
			c.equal(r["restart_required"], true)
			c.check(strings.Contains(strings.ToLower(r["message"].(string)), "restart"), "missing restart message: %v", r)
			cfg := c.obj("/config/resolver")
			c.equal(jsonAs[M](c, c.post("/config/resolver", cfg))["restart_required"], true)
		}},
		{"test_udp_and_tcp_resolution_through_nonstandard_upstream_port", func(c *caseEnv) {
			upstreams := []M{{"address": c.h.upstreamIP + ":5353", "protocol": "udp"}}
			path := c.h.seed(c, c.TempDir(), M{"upstreams": upstreams, "auto_block_upstreams": upstreams})
			s := c.h.start(c.T, path, "")
			s.ready(c)
			for _, tcp := range []bool{false, true} {
				if err := s.rcode("resolves-fine.test", dns.TypeA, tcp, dns.RcodeSuccess); err != nil {
					c.Fatal(err)
				}
			}
		}},
		{"test_udp_truncation_is_followed_by_complete_tcp_response", func(c *caseEnv) {
			q := new(dns.Msg)
			q.SetQuestion("large-response.test.", dns.TypeTXT)
			q.SetEdns0(1232, false)
			u, err := c.s.exchange(q, false)
			if err != nil {
				c.Fatal(err)
			}
			c.check(u.Truncated, "UDP response not truncated: %s", u)
			r, err := c.s.exchange(q, true)
			if err != nil {
				c.Fatal(err)
			}
			c.check(!r.Truncated && len(r.Answer) > 0, "TCP response incomplete: %s", r)
		}},
		{"test_nxdomain_preserves_soa_authority", func(c *caseEnv) {
			r := c.expect("negative-soa.test", dns.TypeA, dns.RcodeNameError)
			found := false
			for _, rr := range r.Ns {
				found = found || rr.Header().Rrtype == dns.TypeSOA
			}
			c.check(found, "negative answer lost SOA: %s", r)
		}},
		{"test_concurrent_identical_misses_are_stable", func(c *caseEnv) {
			var wg sync.WaitGroup
			errors := make(chan error, 64)
			slots := make(chan struct{}, 16)
			for range 64 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					slots <- struct{}{}
					defer func() { <-slots }()
					if err := c.s.rcode("concurrent-miss.test", dns.TypeA, false, dns.RcodeNameError); err != nil {
						errors <- err
					}
				}()
			}
			wg.Wait()
			close(errors)
			for err := range errors {
				c.Error(err)
			}
		}},
		{"test_doh_failure_is_fail_closed_without_explicit_fallback", func(c *caseEnv) {
			cfg := c.restore("/config/doh")
			cfg["encrypted_upstream_enabled"] = true
			cfg["encrypted_upstream_allow_plaintext_fallback"] = false
			cfg["encrypted_upstream_url"] = "https://127.0.0.1:1/dns-query"
			c.post("/config/doh", cfg)
			c.expect("doh-fail-closed.test", dns.TypeA, dns.RcodeServerFailure)
		}},
		{"test_doh_failure_uses_plaintext_only_when_enabled", func(c *caseEnv) {
			cfg := c.restore("/config/doh")
			cfg["encrypted_upstream_enabled"] = true
			cfg["encrypted_upstream_allow_plaintext_fallback"] = true
			cfg["encrypted_upstream_url"] = "https://127.0.0.1:1/dns-query"
			c.post("/config/doh", cfg)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_sinkhole_does_not_learn_global_malicious_ip", func(c *caseEnv) {
			before := c.obj("/lists/malicious-ips")["ips"]
			c.expect("sinkholed.test", dns.TypeA, dns.RcodeNameError)
			after := c.obj("/lists/malicious-ips")["ips"]
			c.equal(after, before)
			for _, ip := range after.([]any) {
				c.check(ip != "0.0.0.0", "sinkhole learned as global IP")
			}
		}},
	}
}

func pauseCases() []testCase {
	return []testCase{
		{"test_global_pause_bypasses_service_block", func(c *caseEnv) {
			c.services(nil, customService("protection-test-global-svc", "resolves-fine.test", true))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.pause("global", "", 0)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_service_pause_bypasses_only_that_service", func(c *caseEnv) {
			c.services(nil, customService("protection-test-svc-a", "resolves-fine.test", true), customService("protection-test-svc-b", "malicious-ip.test", true))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.expect("malicious-ip.test", dns.TypeA, dns.RcodeNameError)
			c.pause("service", "protection-test-svc-a", 0)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.expect("malicious-ip.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_early_resume_is_immediate", func(c *caseEnv) {
			c.services(nil, customService("protection-test-resume-svc", "resolves-fine.test", true))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.pause("service", "protection-test-resume-svc", 0)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.post("/protection/resume", M{"scope": "service", "id": "protection-test-resume-svc"})
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_re_pause_already_paused_scope_returns_409", func(c *caseEnv) {
			c.pause("service", "protection-test-409-svc", 0)
			c.post("/protection/pause", M{"scope": "service", "id": "protection-test-409-svc"}, 409)
		}},
		{"test_category_pause_removes_category_from_blocklist", func(c *caseEnv) {
			cfg := c.restore("/config/blocklist")
			cfg["blocklist_categories"] = []M{{"id": "protection-test-category", "name": "Protection Test Category", "urls": []string{"file:///etc/dns-deny/category-test.txt"}, "enabled": true}}
			c.post("/config/blocklist", cfg)
			c.awaitCode("resolves-fine.test", dns.RcodeNameError, 15*time.Second)
			c.pause("category", "protection-test-category", 0)
			c.awaitCode("resolves-fine.test", dns.RcodeSuccess, 15*time.Second)
		}},
		{"test_auto_expiry_reenables_after_default_duration", func(c *caseEnv) {
			c.services(nil, customService("protection-test-expiry-svc", "resolves-fine.test", true))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.pause("service", "protection-test-expiry-svc", 0)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.awaitCode("resolves-fine.test", dns.RcodeNameError, 45*time.Second)
		}},
		{"test_protection_status_reports_bounded_countdown", func(c *caseEnv) {
			defaultDuration := c.obj("/protection/status")["default_duration_secs"].(float64)
			before := float64(time.Now().UnixMilli()) / 1000
			c.pause("service", "protection-test-status-svc", 0)
			after := float64(time.Now().UnixMilli()) / 1000
			until := c.obj("/protection/status")["service_pauses"].(map[string]any)["protection-test-status-svc"].(float64)
			anchor := until - defaultDuration
			c.check(anchor >= before-1 && anchor <= after+1, "pause anchored at %f outside [%f,%f]", anchor, before-1, after+1)
		}},
	}
}

func expectStatus(r response, want int) error {
	if r.status != want {
		return fmt.Errorf("HTTP %d: %s", r.status, r.body)
	}
	return nil
}
