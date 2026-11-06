package integration

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	_ "modernc.org/sqlite"
)

func database(c *caseEnv, path string) *sql.DB {
	c.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		c.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		c.Fatal(err)
	}
	return db
}
func stateLayout(c *caseEnv) (string, string) {
	c.Helper()
	dir := c.TempDir()
	return c.h.seed(c, dir, nil), filepath.Join(dir, "data")
}
func startState(c *caseEnv, path, data string) *instance {
	c.Helper()
	s := c.h.start(c.T, path, data)
	s.ready(c)
	c.s = s
	return s
}
func stopState(c *caseEnv, s *instance)   { c.Helper(); dockerMust(c, "stop", "--time", "2", s.id) }
func logs(c *caseEnv, s *instance) string { c.Helper(); return dockerMust(c, "logs", s.id) }
func removeState(c *caseEnv, data string) {
	c.Helper()
	files, err := filepath.Glob(filepath.Join(data, "state.db*"))
	if err != nil {
		c.Fatal(err)
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			c.Fatal(err)
		}
	}
}
func tables(c *caseEnv, path string) []string {
	c.Helper()
	db := database(c, path)
	defer db.Close()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		c.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			c.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		c.Fatal(err)
	}
	return names
}

func stateCases() []testCase {
	return []testCase{
		{"test_config_persistence_across_restarts_and_toml_independence", func(c *caseEnv) {
			path, data := stateLayout(c)
			first := startState(c, path, data)
			text := logs(c, first)
			c.check(strings.Contains(text, "Seeded configuration into") && strings.Contains(text, "revision 1"), "fresh state not seeded: %s", text)
			db := database(c, filepath.Join(data, "state.db"))
			var singleton, revision int64
			err := db.QueryRow("SELECT singleton,revision FROM config_state").Scan(&singleton, &revision)
			db.Close()
			if err != nil {
				c.Fatal(err)
			}
			c.equal(singleton, int64(1))
			c.equal(revision, int64(1))
			c.post("/config/safesearch", M{"enforce_safesearch": true})
			doh := c.obj("/config/doh")
			doh["encrypted_upstream_allow_plaintext_fallback"] = true
			c.post("/config/doh", doh)
			c.post("/local-dns", M{"name": "persist-test.internal", "record_type": "A", "value": "10.99.99.1"})
			c.post("/network/policy", M{"ip": "192.0.2.100", "policy": "block"})
			c.post("/config/upstreams", M{"upstreams": []M{{"address": c.h.upstreamIP + ":53", "protocol": "udp", "tls_sni": nil, "doh_path": nil}, {"address": "192.0.2.53:53", "protocol": "udp", "tls_sni": nil, "doh_path": nil}}})
			c.post("/protection/pause", M{"scope": "global", "duration_secs": 3600})
			c.check(hasAnswer(c.expect("persist-test.internal", dns.TypeA, dns.RcodeSuccess), dns.TypeA, "10.99.99.1"), "local record missing before restart")
			stopState(c, first)
			second := startState(c, path, data)
			text = logs(c, second)
			c.check(strings.Contains(text, "Loaded configuration from SQLite state database"), "restart did not use state: %s", text)
			db = database(c, filepath.Join(data, "state.db"))
			err = db.QueryRow("SELECT revision FROM config_state").Scan(&revision)
			db.Close()
			if err != nil {
				c.Fatal(err)
			}
			c.check(revision >= 2, "revision did not advance: %d", revision)
			c.check(regexp.MustCompile(fmt.Sprintf(`revision %d\b`, revision)).MatchString(text), "startup log does not match revision %d: %s", revision, text)
			c.equal(c.obj("/config/safesearch")["enforce_safesearch"], true)
			c.equal(c.obj("/config/doh")["encrypted_upstream_allow_plaintext_fallback"], true)
			found := false
			for _, r := range jsonAs[[]M](c, c.get("/local-dns")) {
				found = found || (r["name"] == "persist-test.internal" && r["value"] == "10.99.99.1")
			}
			c.check(found, "local record not persisted")
			c.equal(c.obj("/config")["device_policies"].(map[string]any)["192.0.2.100"], "block")
			found = false
			for _, r := range c.obj("/config/upstreams")["upstreams"].([]any) {
				found = found || r.(map[string]any)["address"] == "192.0.2.53:53"
			}
			c.check(found, "upstreams not persisted")
			c.check(c.obj("/protection/status")["global_paused_until"] != nil, "global pause not persisted")
			c.check(hasAnswer(c.expect("persist-test.internal", dns.TypeA, dns.RcodeSuccess), dns.TypeA, "10.99.99.1"), "local record missing after restart")
			stopState(c, second)
			c.h.seed(c, filepath.Dir(path), M{"enforce_safesearch": false, "local_dns_records": []M{}})
			third := startState(c, path, data)
			c.equal(c.obj("/config/safesearch")["enforce_safesearch"], true)
			found = false
			for _, r := range jsonAs[[]M](c, c.get("/local-dns")) {
				found = found || r["name"] == "persist-test.internal"
			}
			c.check(found, "edited TOML overwrote saved local record")
			stopState(c, third)
			removeState(c, data)
			fourth := startState(c, path, data)
			text = logs(c, fourth)
			c.check(strings.Contains(text, "Seeded configuration into") && strings.Contains(text, "revision 1"), "empty state not re-seeded: %s", text)
			c.equal(c.obj("/config/safesearch")["enforce_safesearch"], false)
			c.equal(len(jsonAs[[]M](c, c.get("/local-dns"))), 0)
		}},
		{"test_forced_write_failure_leaves_live_snapshot_and_dns_unaffected", func(c *caseEnv) {
			path, data := stateLayout(c)
			startState(c, path, data)
			c.equal(c.obj("/config/safesearch")["enforce_safesearch"], false)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			db := database(c, filepath.Join(data, "state.db"))
			_, err := db.Exec("DROP TABLE config_state")
			db.Close()
			if err != nil {
				c.Fatal(err)
			}
			r := c.post("/config/safesearch", M{"enforce_safesearch": true}, 500)
			c.check(!strings.Contains(strings.ToLower(string(r.body)), "sqlite"), "SQLite details leaked: %s", r.body)
			c.equal(c.obj("/config/safesearch")["enforce_safesearch"], false)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
		}},
		{"test_corrupt_or_unsupported_database_fails_startup_without_seed_fallback", func(c *caseEnv) {
			path, data := stateLayout(c)
			if err := os.MkdirAll(data, 0777); err != nil {
				c.Fatal(err)
			}
			db := database(c, filepath.Join(data, "state.db"))
			_, err := db.Exec("PRAGMA user_version=99")
			db.Close()
			if err != nil {
				c.Fatal(err)
			}
			s := c.h.start(c.T, path, data, true)
			out, err := docker(8*time.Second, "wait", s.id)
			if err != nil {
				c.Fatal(err)
			}
			c.check(out != "0", "unsupported state exited successfully")
			text := logs(c, s)
			lower := strings.ToLower(text)
			c.check(strings.Contains(lower, "unsupported") || strings.Contains(lower, "schema"), "missing schema error: %s", text)
			c.check(!strings.Contains(text, "Seeded configuration"), "unsupported state silently re-seeded")
		}},
		{"test_dns_and_api_reads_continue_from_memory_if_db_becomes_unavailable", func(c *caseEnv) {
			path, data := stateLayout(c)
			startState(c, path, data)
			removeState(c, data)
			c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			c.get("/config/safesearch")
			c.get("/local-dns")
			c.get("/stats")
		}},
		{"test_logs_db_and_state_db_remain_separate", func(c *caseEnv) {
			path, data := stateLayout(c)
			startState(c, path, data)
			for range 3 {
				c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
			}
			poll(c, 5*time.Second, "query log flush", func() error {
				if _, err := os.Stat(filepath.Join(data, "logs.db")); err != nil {
					return err
				}
				names := tables(c, filepath.Join(data, "logs.db"))
				for _, name := range names {
					if strings.HasPrefix(name, "logs_") {
						return nil
					}
				}
				return fmt.Errorf("no log partition yet")
			})
			stateTables := tables(c, filepath.Join(data, "state.db"))
			c.check(contains(stateTables, "config_state"), "state table missing")
			for _, name := range stateTables {
				c.check(!strings.HasPrefix(name, "logs_"), "logs leaked into state database")
			}
			c.check(!contains(tables(c, filepath.Join(data, "logs.db")), "config_state"), "config leaked into logs database")
		}},
	}
}
