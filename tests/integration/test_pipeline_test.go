package integration

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIntegration(t *testing.T) {
	h := newHarness(t)
	groups := []struct {
		name  string
		cases []testCase
	}{
		{"Smoke", smokeCases()}, {"StatePersistence", stateCases()}, {"DNSResolution", resolutionCases()},
		{"AllowDenyLists", listCases()}, {"DevicePolicy", deviceCases()}, {"FilterTiers", filterCases()},
		{"LocalDNS", localCases()}, {"ProtectionPause", pauseCases()}, {"RateLimit", rateCases()},
		{"SafeSearch", safeSearchCases()}, {"Services", serviceCases()}, {"EndpointCoverage", endpointCases()},
	}
	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			if group.name == "RateLimit" {
				server := h.start(t, h.seed(t, t.TempDir(), nil), "")
				server.ready(t)
				runCases(t, h, group.cases, server)
			} else {
				runCases(t, h, group.cases)
			}
		})
	}
}

func smokeCases() []testCase {
	return []testCase{
		{"test_container_is_healthy_and_dns_resolves", func(c *caseEnv) {
			c.get("/stats")
			r := c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.check(hasAnswer(r, dns.TypeA, "93.184.216.34"), "missing canned A answer: %s", r)
		}},
		{"test_seeded_blocklist_entry_is_blocked", func(c *caseEnv) { c.expect("exact-blocked.test", dns.TypeA, dns.RcodeNameError) }},
		{"test_unrelated_domain_not_blocked", func(c *caseEnv) { c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess) }},
	}
}

func listCases() []testCase {
	return []testCase{
		{"test_get_allow_and_deny_lists_reflect_current_state", func(c *caseEnv) {
			c.rule("deny", "visible-deny.test")
			c.check(contains(jsonAs[[]string](c, c.get("/lists/deny")), "visible-deny.test"), "deny missing")
			c.rule("allow", "visible-allow.test")
			c.check(contains(jsonAs[[]string](c, c.get("/lists/allow")), "visible-allow.test"), "allow missing")
		}},
		{"test_adding_to_allow_removes_same_domain_from_deny", func(c *caseEnv) {
			c.rule("deny", "resolves-fine.test")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.rule("allow", "resolves-fine.test")
			c.check(!contains(jsonAs[[]string](c, c.get("/lists/deny")), "resolves-fine.test"), "deny retained after allow")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_adding_to_deny_removes_same_domain_from_allow", func(c *caseEnv) {
			c.rule("allow", "sub.trie-blocked.test")
			c.expect("sub.trie-blocked.test", dns.TypeA, dns.RcodeSuccess)
			c.rule("deny", "sub.trie-blocked.test")
			c.check(!contains(jsonAs[[]string](c, c.get("/lists/allow")), "sub.trie-blocked.test"), "allow retained after deny")
			c.expect("sub.trie-blocked.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_lists_summary_reports_counts", func(c *caseEnv) {
			c.rule("deny", "summary-count-deny.test")
			summary := c.obj("/lists/summary")
			c.check(summary["local_deny"].(map[string]any)["count"].(float64) >= 1, "missing local deny count: %v", summary)
			_, categories := summary["categories"]
			_, sources := summary["uncategorized_sources"]
			c.check(categories && sources, "missing source summary: %v", summary)
		}},
	}
}

func filterCases() []testCase {
	return []testCase{
		{"test_exact_tier_seeded_deny_blocks", func(c *caseEnv) { c.expect("exact-blocked.test", dns.TypeA, dns.RcodeNameError) }},
		{"test_trie_tier_blocks_unlisted_subdomain", func(c *caseEnv) { c.expect("anything.trie-blocked.test", dns.TypeA, dns.RcodeNameError) }},
		{"test_regex_tier_deny_blocks_matching_pattern", func(c *caseEnv) {
			c.rule("regex-deny", `^regex-blocked\.test$`)
			c.expect("regex-blocked.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_invalid_regex_pattern_rejected", func(c *caseEnv) { c.post("/lists/regex-deny", M{"pattern": "(unclosed["}, 400) }},
		{"test_exact_tier_allow_overrides_trie_tier_deny", func(c *caseEnv) {
			c.expect("sub.trie-blocked.test", dns.TypeA, dns.RcodeNameError)
			c.rule("allow", "sub.trie-blocked.test")
			c.check(hasAnswer(c.expect("sub.trie-blocked.test", dns.TypeA, dns.RcodeSuccess), dns.TypeA, "203.0.113.60"), "allow must expose real upstream A answer")
		}},
		{"test_regex_tier_allow_overrides_exact_tier_deny", func(c *caseEnv) {
			c.rule("deny", "resolves-fine.test")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.rule("regex-allow", `^resolves-fine\.test$`)
			c.check(hasAnswer(c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess), dns.TypeA, "93.184.216.34"), "regex allow must expose real upstream A answer")
		}},
		{"test_removing_deny_entry_unblocks", func(c *caseEnv) {
			c.rule("deny", "temp-blocked.test")
			c.expect("temp-blocked.test", dns.TypeA, dns.RcodeNameError)
			c.del("/lists/deny", M{"pattern": "temp-blocked.test"})
			// This owner is also absent upstream: distinguish removal through API state.
			c.check(!contains(jsonAs[[]string](c, c.get("/lists/deny")), "temp-blocked.test"), "deny not removed")
			c.expect("temp-blocked.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_removing_nonexistent_deny_entry_returns_404", func(c *caseEnv) { c.del("/lists/deny", M{"pattern": "never-denied.test"}, 404) }},
		{"test_filter_check_skipped_for_whitelisted_client", func(c *caseEnv) {
			ip := c.clientIP()
			c.rule("deny", "resolves-fine.test")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.policy(ip, "whitelist")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
	}
}

func localCases() []testCase {
	return []testCase{
		{"test_a_record_served_for_matching_query", func(c *caseEnv) {
			c.local("host-a.local.test", "A", "203.0.113.10")
			r := c.expect("host-a.local.test", dns.TypeA, dns.RcodeSuccess)
			c.equal(len(r.Answer), 1)
			c.check(hasAnswer(r, dns.TypeA, "203.0.113.10"), "wrong A: %s", r)
			c.equal(r.Answer[0].Header().Ttl, uint32(60))
		}},
		{"test_aaaa_record_served_for_matching_query", func(c *caseEnv) {
			c.local("host-aaaa.local.test", "AAAA", "2001:db8::42")
			r := c.expect("host-aaaa.local.test", dns.TypeAAAA, dns.RcodeSuccess)
			c.equal(len(r.Answer), 1)
			c.check(hasAnswer(r, dns.TypeAAAA, "2001:db8::42"), "wrong AAAA: %s", r)
		}},
		{"test_aaaa_only_record_answers_a_query_with_nodata", func(c *caseEnv) {
			c.local("aaaa-only.local.test", "AAAA", "2001:db8::99")
			c.equal(len(c.expect("aaaa-only.local.test", dns.TypeA, dns.RcodeSuccess).Answer), 0)
		}},
		{"test_local_cname_to_local_a_returns_full_chain", func(c *caseEnv) {
			c.local("chain-target.local.test", "A", "203.0.113.20")
			c.local("chain-alias.local.test", "CNAME", "chain-target.local.test")
			r := c.expect("chain-alias.local.test", dns.TypeA, dns.RcodeSuccess)
			c.equal(len(r.Answer), 2)
			c.equal(r.Answer[0].Header().Rrtype, dns.TypeCNAME)
			c.equal(r.Answer[1].Header().Rrtype, dns.TypeA)
			c.check(hasAnswer(r, dns.TypeCNAME, "chain-target.local.test") && hasAnswer(r, dns.TypeA, "203.0.113.20"), "wrong CNAME chain: %s", r)
		}},
		{"test_local_cname_to_external_name_resolves_target_upstream", func(c *caseEnv) {
			c.local("external-alias.local.test", "CNAME", "resolves-fine.test")
			r := c.expect("external-alias.local.test", dns.TypeA, dns.RcodeSuccess)
			c.check(hasAnswer(r, dns.TypeCNAME, "resolves-fine.test") && hasAnswer(r, dns.TypeA, "93.184.216.34"), "incomplete external CNAME chain: %s", r)
		}},
		{"test_cname_record_coexistence_with_a_record_rejected", func(c *caseEnv) {
			c.local("cname-wins.local.test", "A", "203.0.113.11")
			r := c.post("/local-dns", M{"name": "cname-wins.local.test", "record_type": "CNAME", "value": "resolves-fine.test"}, 400)
			c.check(bytesContain(r.body, "CNAME cannot coexist"), "wrong conflict error: %s", r.body)
		}},
		{"test_duplicate_name_and_type_add_rejected", func(c *caseEnv) {
			c.local("dup.local.test", "A", "203.0.113.12")
			c.post("/local-dns", M{"name": "dup.local.test", "record_type": "A", "value": "203.0.113.13"}, 400)
		}},
		{"test_invalid_record_value_rejected", func(c *caseEnv) {
			c.post("/local-dns", M{"name": "bad-value.local.test", "record_type": "A", "value": "not-an-ip"}, 400)
		}},
		{"test_invalid_record_type_rejected", func(c *caseEnv) {
			c.post("/local-dns", M{"name": "bad-type.local.test", "record_type": "MX", "value": "203.0.113.14"}, 400)
		}},
		{"test_delete_removes_record_and_invalidates_cache", func(c *caseEnv) {
			c.local("to-delete.local.test", "A", "203.0.113.15")
			c.check(hasAnswer(c.expect("to-delete.local.test", dns.TypeA, dns.RcodeSuccess), dns.TypeA, "203.0.113.15"), "missing address before delete")
			c.del("/local-dns", M{"name": "to-delete.local.test", "record_type": "A"})
			c.expect("to-delete.local.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_delete_nonexistent_record_returns_404", func(c *caseEnv) { c.del("/local-dns", M{"name": "never-existed.local.test", "record_type": "A"}, 404) }},
	}
}

func deviceCases() []testCase {
	return []testCase{
		{"test_static_block_policy_refuses", func(c *caseEnv) {
			ip := c.clientIP()
			c.policy(ip, "block")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeRefused)
		}},
		{"test_static_whitelist_bypasses_blocklist_deny", func(c *caseEnv) {
			ip := c.clientIP()
			c.rule("deny", "resolves-fine.test")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.policy(ip, "whitelist")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_schedule_takes_precedence_over_static_policy", func(c *caseEnv) {
			ip := c.clientIP()
			c.policy(ip, "whitelist")
			// Pick a three-minute window containing now, including midnight wrap.
			now := time.Now().UTC()
			start := now.Add(-time.Minute).Format("15:04")
			end := now.Add(2 * time.Minute).Format("15:04")
			c.post("/network/schedules", M{"ip": ip, "policy": "block", "days": []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, "start_time": start, "end_time": end}, 200, 201)
			c.cleanup("DELETE", "/network/schedules/"+ip, nil)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeRefused)
		}},
		{"test_policy_default_clears_override", func(c *caseEnv) {
			ip := c.clientIP()
			c.policy(ip, "block")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeRefused)
			c.post("/network/policy", M{"ip": ip, "policy": "default"})
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_device_pause_expires_and_restores_static_block", func(c *caseEnv) {
			ip := c.clientIP()
			c.policy(ip, "block")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeRefused)
			c.pause("device", ip, 3)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.awaitCode("resolves-fine.test", dns.RcodeRefused, 8*time.Second)
			_, present := c.obj("/protection/status")["device_pauses"].(map[string]any)[ip]
			c.check(!present, "expired device pause still active")
		}},
		{"test_device_pause_resume_rechecks_blocked_cached_domain", func(c *caseEnv) {
			ip := c.clientIP()
			c.rule("deny", "resolves-fine.test")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.pause("device", ip, 300)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.post("/protection/resume", M{"scope": "device", "id": ip})
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
		}},
	}
}

func customService(id, domain string, enabled bool) M {
	return M{"id": id, "name": "Integration service " + id, "description": "integration test", "wildcards": []string{domain}, "enabled": enabled}
}
func (c *caseEnv) services(builtins []string, custom ...M) {
	c.Helper()
	original := c.obj("/config")
	c.cleanup("POST", "/config/services", M{"blocked_services": original["blocked_services"], "custom_services": original["custom_services"]})
	if builtins == nil {
		builtins = []string{}
	}
	if custom == nil {
		custom = []M{}
	}
	c.post("/config/services", M{"blocked_services": builtins, "custom_services": custom})
}

func serviceCases() []testCase {
	return []testCase{
		{"test_builtin_service_blocks_base_domain", func(c *caseEnv) {
			c.services([]string{"facebook"})
			c.expect("facebook.com", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_builtin_service_blocks_wildcard_subdomain", func(c *caseEnv) {
			c.services([]string{"facebook"})
			c.expect("instagram.com", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_unrelated_domain_unaffected_by_service_block", func(c *caseEnv) {
			c.services([]string{"facebook"})
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_enabled_custom_service_blocks_its_wildcard", func(c *caseEnv) {
			c.services(nil, customService("custom-test-svc-enabled", "resolves-fine.test", true))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
		}},
		{"test_disabled_custom_service_does_not_block", func(c *caseEnv) {
			c.services(nil, customService("custom-test-svc-disabled", "resolves-fine.test", false))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_service_block_skipped_for_whitelisted_client", func(c *caseEnv) {
			ip := c.clientIP()
			c.services(nil, customService("custom-test-svc-bypass", "resolves-fine.test", true))
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeNameError)
			c.policy(ip, "whitelist")
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
	}
}

func safeSearchCases() []testCase {
	var cases []testCase
	for _, entry := range []struct{ name, target string }{{"google.com", "forcesafesearch.google.com"}, {"www.google.com", "forcesafesearch.google.com"}, {"youtube.com", "restrict.youtube.com"}, {"www.youtube.com", "restrict.youtube.com"}, {"m.youtube.com", "restrict.youtube.com"}, {"youtube-nocookie.com", "restrict.youtube.com"}, {"bing.com", "strict.bing.com"}, {"www.bing.com", "strict.bing.com"}} {
		cases = append(cases, testCase{"test_known_domain_rewritten_to_safesearch_target/" + entry.name, func(c *caseEnv) {
			c.restore("/config/safesearch")
			c.post("/config/safesearch", M{"enforce_safesearch": true})
			r := c.expect(entry.name, dns.TypeA, dns.RcodeSuccess)
			c.equal(len(r.Answer), 1)
			c.check(hasAnswer(r, dns.TypeCNAME, entry.target), "wrong SafeSearch target: %s", r)
			c.equal(r.Answer[0].Header().Ttl, uint32(60))
		}})
	}
	cases = append(cases,
		testCase{"test_near_miss_domain_not_in_table_is_not_rewritten", func(c *caseEnv) {
			c.restore("/config/safesearch")
			c.post("/config/safesearch", M{"enforce_safesearch": true})
			r := c.expect("mail.google.com", dns.TypeA, dns.RcodeNameError)
			for _, rr := range r.Answer {
				c.check(rr.Header().Rrtype != dns.TypeCNAME, "near miss rewritten")
			}
		}},
		testCase{"test_disabled_flag_does_not_rewrite", func(c *caseEnv) {
			c.restore("/config/safesearch")
			c.post("/config/safesearch", M{"enforce_safesearch": false})
			r := c.expect("google.com", dns.TypeA, dns.RcodeNameError)
			for _, rr := range r.Answer {
				c.check(rr.Header().Rrtype != dns.TypeCNAME, "disabled SafeSearch rewrote")
			}
		}},
		testCase{"test_local_dns_record_takes_precedence_over_safesearch", func(c *caseEnv) {
			c.restore("/config/safesearch")
			c.post("/config/safesearch", M{"enforce_safesearch": true})
			c.local("google.com", "A", "203.0.113.9")
			r := c.expect("google.com", dns.TypeA, dns.RcodeSuccess)
			c.equal(len(r.Answer), 1)
			c.check(hasAnswer(r, dns.TypeA, "203.0.113.9"), "local record lost to SafeSearch: %s", r)
		}},
	)
	return cases
}

func rateCases() []testCase {
	recoverRate := func(c *caseEnv) { c.awaitCode("resolves-fine.test", dns.RcodeSuccess, 5*time.Second) }
	burst := func(c *caseEnv) map[int]int {
		codes := map[int]int{}
		for range 200 {
			r, err := c.s.query("resolves-fine.test", dns.TypeA, false)
			if err != nil {
				c.Fatal(err)
			}
			codes[r.Rcode]++
		}
		return codes
	}
	return []testCase{
		{"test_under_limit_traffic_passes", func(c *caseEnv) {
			recoverRate(c)
			for range 5 {
				c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			}
		}},
		{"test_over_limit_traffic_is_refused", func(c *caseEnv) {
			recoverRate(c)
			c.Cleanup(func() { recoverRate(c) })
			codes := burst(c)
			c.check(codes[dns.RcodeRefused] > 0 && codes[dns.RcodeSuccess] > 0, "expected successful and refused burst responses: %v", codes)
		}},
		{"test_rate_limit_applies_even_to_whitelisted_client", func(c *caseEnv) {
			recoverRate(c)
			ip := c.clientIP()
			c.policy(ip, "whitelist")
			c.Cleanup(func() { recoverRate(c) })
			codes := burst(c)
			c.check(codes[dns.RcodeRefused] > 0, "whitelist bypassed rate limit: %v", codes)
		}},
		{"test_rate_limit_applies_during_device_pause", func(c *caseEnv) {
			recoverRate(c)
			ip := c.clientIP()
			c.pause("device", ip, 300)
			c.Cleanup(func() { recoverRate(c) })
			codes := burst(c)
			c.check(codes[dns.RcodeRefused] > 0, "device pause bypassed rate limit: %v", codes)
		}},
	}
}
