package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func endpointCases() []testCase {
	var cases []testCase
	for _, entry := range []struct{ name, path string }{
		{"test_stats_top_blocked", "/stats/top-blocked"}, {"test_stats_top_clients", "/stats/top-clients"}, {"test_stats_queries_over_time", "/stats/queries-over-time"}, {"test_stats_query_types", "/stats/query-types"}, {"test_stats_upstreams", "/stats/upstreams"},
		{"test_lists_auto_blocked", "/lists/auto-blocked"}, {"test_lists_sources_status", "/lists/sources/status"}, {"test_network_schedules_get", "/network/schedules"},
	} {
		cases = append(cases, testCase{entry.name, func(c *caseEnv) { c.get(entry.path) }})
	}
	for _, entry := range []struct{ name, path string }{
		{"test_config_doh_round_trip", "/config/doh"}, {"test_config_detection_round_trip", "/config/detection"}, {"test_config_resolver_round_trip", "/config/resolver"}, {"test_protection_settings_round_trip", "/protection/settings"}, {"test_network_device_blocking_round_trip", "/network/device-blocking"},
	} {
		cases = append(cases, testCase{entry.name, func(c *caseEnv) { c.post(entry.path, c.obj(entry.path)) }})
	}
	return append(cases,
		testCase{"test_lists_auto_blocked_learn_and_remove", func(c *caseEnv) {
			c.expect("sinkholed.test", dns.TypeA, dns.RcodeNameError)
			poll(c, 10*time.Second, "auto-deny persisted", func() error {
				for _, name := range c.obj("/lists/auto-blocked")["domains"].([]any) {
					if name == "sinkholed.test" {
						return nil
					}
				}
				return fmt.Errorf("sinkholed.test not learned")
			})
			c.del("/lists/auto-blocked", M{"pattern": "sinkholed.test"})
			for _, name := range c.obj("/lists/auto-blocked")["domains"].([]any) {
				c.check(name != "sinkholed.test", "auto-deny not removed")
			}
			c.del("/lists/auto-blocked", M{"pattern": "sinkholed.test"}, 404)
		}},
		testCase{"test_lists_malicious_ips_round_trip", func(c *caseEnv) {
			c.get("/lists/malicious-ips")
			c.post("/lists/malicious-ips", M{"ip": "203.0.113.77"})
			c.cleanup("DELETE", "/lists/malicious-ips", M{"ip": "203.0.113.77"})
			ips := c.obj("/lists/malicious-ips")["ips"].([]any)
			found := false
			for _, ip := range ips {
				found = found || ip == "203.0.113.77"
			}
			c.check(found, "added IP missing")
			c.del("/lists/malicious-ips", M{"ip": "203.0.113.77"})
		}},
		testCase{"test_lists_sources_sync", func(c *caseEnv) { c.equal(jsonAs[M](c, c.post("/lists/sources/sync", nil))["status"], "sync_started") }},
		testCase{"test_lists_sources_invalidate", func(c *caseEnv) {
			c.equal(jsonAs[M](c, c.post("/lists/sources/invalidate", M{"url": "file:///etc/dns-deny/blocklist-test.txt"}))["status"], "invalidated")
		}},
		testCase{"test_get_config_masks_api_key", func(c *caseEnv) { c.equal(c.obj("/config")["api_key"], "********") }},
		testCase{"test_config_password_round_trip", func(c *caseEnv) {
			original := c.s.api.key
			temporary := "integration-coverage-temp-pw-1"
			c.post("/config/password", M{"current_password": original, "new_password": temporary})
			c.s.api.key = temporary
			c.Cleanup(func() {
				c.post("/config/password", M{"current_password": temporary, "new_password": original})
				c.s.api.key = original
			})
			c.get("/stats")
			stale := *c.s.api
			stale.key = original
			r, err := stale.call(context.Background(), "GET", "/stats", nil)
			if err != nil {
				c.Fatal(err)
			}
			c.equal(r.status, 401)
		}},
		testCase{"test_network_aliases_round_trip", func(c *caseEnv) {
			c.get("/network/aliases")
			c.post("/network/aliases", M{"identifier": "203.0.113.88", "name": "coverage-test-alias"})
			c.cleanup("DELETE", "/network/aliases/203.0.113.88", nil)
			found := false
			for _, alias := range jsonAs[[]M](c, c.get("/network/aliases")) {
				found = found || alias["identifier"] == "203.0.113.88"
			}
			c.check(found, "alias missing")
			c.del("/network/aliases/203.0.113.88", nil)
		}},
		testCase{"test_logs_query", func(c *caseEnv) { _, ok := c.obj("/logs?limit=10")["logs"]; c.check(ok, "logs key missing") }},
		testCase{"test_logs_export_csv", func(c *caseEnv) {
			c.check(strings.HasPrefix(c.get("/logs/export").header.Get("Content-Type"), "text/csv"), "CSV content type missing")
		}},
		testCase{"test_diagnostics", func(c *caseEnv) {
			body := c.obj("/diagnostics")
			status := body["status"].(string)
			c.check(contains([]string{"healthy", "warning", "critical"}, status), "unknown diagnostics status: %s", status)
			c.check(len(body["components"].([]any)) > 0, "diagnostics components empty")
		}},
		testCase{"test_diagnostics_probe_matches_deny_list", func(c *caseEnv) {
			c.rule("deny", "probe-coverage-deny.test")
			body := c.obj("/diagnostics/probe?domain=" + escaped("probe-coverage-deny.test"))
			c.equal(body["verdict"], "blocked")
			c.check(strings.Contains(strings.ToLower(body["reason"].(string)), "deny"), "probe reason does not identify deny: %v", body)
		}},
		testCase{"test_diagnostics_probe_allows_unlisted_domain", func(c *caseEnv) {
			c.equal(c.obj("/diagnostics/probe?domain=probe-coverage-unlisted.test")["verdict"], "allowed")
		}},
		testCase{"test_live_tail_stream_opens", func(c *caseEnv) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", c.s.apiURL+"/tail", nil)
			if err != nil {
				c.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+c.s.api.key)
			r, err := c.s.api.client.Do(req)
			if err != nil {
				c.Fatal(err)
			}
			defer r.Body.Close()
			c.equal(r.StatusCode, 200)
			c.check(strings.HasPrefix(r.Header.Get("Content-Type"), "text/event-stream"), "SSE content type missing")
		}},
	)
}
