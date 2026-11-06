package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
)

const apiKey = "test-integration-api-key-do-not-use"

type M = map[string]any

type harness struct {
	t                                           *testing.T
	root, configDir, network, upstreamIP, image string
	base                                        *instance
}

type instance struct {
	h                    *harness
	id, udp, tcp, apiURL string
	api                  *apiClient
}

type apiClient struct {
	base, key string
	client    *http.Client
}

type response struct {
	status int
	body   []byte
	header http.Header
}

func docker(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func dockerMust(t testing.TB, args ...string) string {
	t.Helper()
	out, err := docker(45*time.Second, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	h := &harness{t: t, root: root, configDir: filepath.Join(root, "tests/integration/docker/configs"), image: os.Getenv("DNS_DENY_TEST_IMAGE")}
	if h.image == "" {
		h.image = "dns-deny:go-integration"
		t.Log("building current DNS Deny image")
		if _, err := docker(20*time.Minute, "build", "-f", filepath.Join(root, "deploy/Dockerfile"), "-t", h.image, root); err != nil {
			t.Fatal(err)
		}
	}
	mockImage := os.Getenv("DNS_DENY_MOCK_IMAGE")
	if mockImage == "" {
		mockImage = "dns-deny-mock:go-integration"
		t.Log("building Go mock resolver image")
		if _, err := docker(10*time.Minute, "build", "-f", filepath.Join(root, "tests/integration/docker/mock_upstream/Dockerfile.mock_upstream"), "-t", mockImage, filepath.Join(root, "tests/integration")); err != nil {
			t.Fatal(err)
		}
	}
	h.network = dockerMust(t, "network", "create", "--label", "dns-deny.test=integration", fmt.Sprintf("dns-deny-go-%d-%d", os.Getpid(), time.Now().UnixNano()))
	t.Cleanup(func() {
		if _, err := docker(30*time.Second, "network", "rm", h.network); err != nil {
			t.Errorf("network cleanup: %v", err)
		}
	})
	mockID := dockerMust(t, "run", "-d", "--network", h.network, "--label", "dns-deny.test=integration", "-p", "127.0.0.1::53/udp", mockImage)
	h.cleanupContainer(t, mockID)
	h.upstreamIP = dockerMust(t, "inspect", "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`, mockID)
	mockPort := publishedPort(t, mockID, "53/udp")
	poll(t, 15*time.Second, "Go mock resolver ready", func() error {
		q := new(dns.Msg)
		q.SetQuestion("resolves-fine.test.", dns.TypeA)
		r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, mockPort)
		if err != nil {
			return err
		}
		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("rcode=%d", r.Rcode)
		}
		return nil
	})
	path := h.seed(t, t.TempDir(), M{"ratelimit_qps_per_worker": 10000})
	h.base = h.start(t, path, "")
	h.base.ready(t)
	poll(t, 30*time.Second, "seeded blocklist loaded", func() error { return h.base.rcode("exact-blocked.test", dns.TypeA, false, dns.RcodeNameError) })
	return h
}

func (h *harness) cleanupContainer(t *testing.T, id string) {
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := docker(10*time.Second, "logs", "--tail", "250", id)
			t.Logf("container %s logs:\n%s", id, out)
		}
		if _, err := docker(30*time.Second, "rm", "-f", "-v", id); err != nil {
			t.Errorf("container cleanup: %v", err)
		}
	})
}

func publishedPort(t testing.TB, id, port string) string {
	t.Helper()
	return strings.TrimSpace(strings.Split(dockerMust(t, "port", id, port), "\n")[0])
}

func (h *harness) seed(t testing.TB, dir string, overrides M) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.configDir, "base-config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var config M
	if err := toml.Unmarshal([]byte(strings.ReplaceAll(string(data), "__MOCK_UPSTREAM_IP__", h.upstreamIP)), &config); err != nil {
		t.Fatal(err)
	}
	for key, value := range overrides {
		config[key] = value
	}
	encoded, err := toml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, encoded, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (h *harness) start(t *testing.T, configPath, dataDir string, unchecked ...bool) *instance {
	t.Helper()
	args := []string{"run", "-d", "--network", h.network, "--label", "dns-deny.test=integration",
		"-p", "127.0.0.1::1053/udp", "-p", "127.0.0.1::1053/tcp", "-p", "127.0.0.1::8080/tcp",
		"-e", "DNS_CONFIG=/etc/dns-deny/config.toml", "-e", "DNS_STATE_DB=/var/lib/dns-deny/state.db", "-e", "DNS_PORT=1053", "-e", "TZ=UTC", "-e", "RUST_LOG=dns_deny=info,core_dns=info,api=info,logger=info",
		"--mount", "type=bind,src=" + configPath + ",dst=/etc/dns-deny/config.toml,readonly"}
	for _, name := range []string{"blocklist-test.txt", "category-test.txt"} {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(h.configDir, name)+",dst=/etc/dns-deny/"+name+",readonly")
	}
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dataDir, 0777); err != nil {
			t.Fatal(err)
		}
		// Keep bind-mounted SQLite files accessible to the Go test process.
		// The shared container still uses the image's normal service user.
		args = append(args, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--mount", "type=bind,src="+dataDir+",dst=/var/lib/dns-deny")
	}
	id := dockerMust(t, append(args, h.image)...)
	h.cleanupContainer(t, id)
	s := &instance{h: h, id: id}
	if len(unchecked) > 0 && unchecked[0] {
		return s
	}
	s.udp = publishedPort(t, id, "1053/udp")
	s.tcp = publishedPort(t, id, "1053/tcp")
	s.apiURL = "http://" + publishedPort(t, id, "8080/tcp") + "/api/v1"
	s.api = &apiClient{base: s.apiURL, key: apiKey, client: &http.Client{Timeout: 10 * time.Second}}
	t.Cleanup(s.api.client.CloseIdleConnections)
	return s
}

func (s *instance) ready(t testing.TB) {
	t.Helper()
	poll(t, 30*time.Second, "Admin API ready", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := s.api.call(ctx, "GET", "/stats", nil)
		if err != nil {
			return err
		}
		if r.status != 200 {
			return fmt.Errorf("HTTP %d: %s", r.status, r.body)
		}
		return nil
	})
}

func (s *instance) query(name string, qt uint16, tcp bool) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qt)
	return s.exchange(q, tcp)
}
func (s *instance) exchange(q *dns.Msg, tcp bool) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 3 * time.Second}
	address := s.udp
	if tcp {
		client.Net = "tcp"
		address = s.tcp
	}
	r, _, err := client.Exchange(q, address)
	return r, err
}
func (s *instance) rcode(name string, qt uint16, tcp bool, want int) error {
	r, err := s.query(name, qt, tcp)
	if err != nil {
		return err
	}
	if r.Rcode != want {
		return fmt.Errorf("%s: expected %s, got %s", name, dns.RcodeToString[want], r)
	}
	return nil
}

func (a *apiClient) call(ctx context.Context, method, path string, body any) (response, error) {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return response{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, bytes.NewReader(encoded))
	if err != nil {
		return response{}, err
	}
	if a.key != "" {
		req.Header.Set("Authorization", "Bearer "+a.key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: data}, err
}

func poll(t testing.TB, timeout time.Duration, label string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if last = check(); last == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %v", label, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func jsonAs[T any](t testing.TB, r response) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(r.body, &value); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, r.body)
	}
	return value
}

type caseEnv struct {
	*testing.T
	h *harness
	s *instance
}
type testCase struct {
	name string
	run  func(*caseEnv)
}

func runCases(t *testing.T, h *harness, cases []testCase, server ...*instance) {
	s := h.base
	if len(server) > 0 {
		s = server[0]
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(&caseEnv{T: t, h: h, s: s}) })
	}
}
func (c *caseEnv) check(ok bool, format string, args ...any) {
	c.Helper()
	if !ok {
		c.Fatalf(format, args...)
	}
}
func (c *caseEnv) equal(got, want any) {
	c.Helper()
	if !reflect.DeepEqual(got, want) {
		c.Fatalf("got %#v, want %#v", got, want)
	}
}
func (c *caseEnv) request(method, path string, payload any, status ...int) response {
	c.Helper()
	r, err := c.s.api.call(context.Background(), method, path, payload)
	if err != nil {
		c.Fatal(err)
	}
	if len(status) == 0 {
		status = []int{200}
	}
	for _, want := range status {
		if r.status == want {
			return r
		}
	}
	c.Fatalf("%s %s: got HTTP %d, want %v: %s", method, path, r.status, status, r.body)
	return r
}
func (c *caseEnv) get(path string) response { c.Helper(); return c.request("GET", path, nil) }
func (c *caseEnv) obj(path string) M        { c.Helper(); return jsonAs[M](c, c.get(path)) }
func (c *caseEnv) post(path string, payload any, status ...int) response {
	c.Helper()
	return c.request("POST", path, payload, status...)
}
func (c *caseEnv) del(path string, payload any, status ...int) response {
	c.Helper()
	return c.request("DELETE", path, payload, status...)
}
func (c *caseEnv) cleanup(method, path string, payload any) {
	c.Cleanup(func() {
		r, err := c.s.api.call(context.Background(), method, path, payload)
		if err != nil {
			c.Errorf("cleanup %s: %v", path, err)
		} else if r.status >= 500 {
			c.Errorf("cleanup %s: HTTP %d: %s", path, r.status, r.body)
		}
	})
}
func (c *caseEnv) restore(path string) M {
	c.Helper()
	original := c.obj(path)
	c.cleanup("POST", path, original)
	// Return a distinct map so callers cannot mutate the saved cleanup body.
	return jsonAs[M](c, c.get(path))
}
func (c *caseEnv) expect(name string, qt uint16, want int) *dns.Msg {
	c.Helper()
	r, err := c.s.query(name, qt, false)
	if err != nil {
		c.Fatal(err)
	}
	c.equal(r.Rcode, want)
	return r
}
func (c *caseEnv) awaitCode(name string, want int, timeout time.Duration) {
	c.Helper()
	poll(c, timeout, "DNS rcode for "+name, func() error { return c.s.rcode(name, dns.TypeA, false, want) })
}
func (c *caseEnv) rule(kind, pattern string) {
	c.Helper()
	body := M{"pattern": pattern}
	c.post("/lists/"+kind, body)
	c.cleanup("DELETE", "/lists/"+kind, body)
}
func (c *caseEnv) local(name, qt, value string) {
	c.Helper()
	c.post("/local-dns", M{"name": name, "record_type": qt, "value": value})
	c.cleanup("DELETE", "/local-dns", M{"name": name, "record_type": qt})
}
func (c *caseEnv) clientIP() string {
	c.Helper()
	c.expect("resolves-fine.test", dns.TypeA, dns.RcodeSuccess)
	var ip string
	poll(c, 5*time.Second, "client IP in device table", func() error {
		devices := jsonAs[[]M](c, c.get("/network/devices"))
		if len(devices) != 1 {
			return fmt.Errorf("expected one client, got %v", devices)
		}
		ip = devices[0]["ip"].(string)
		return nil
	})
	return ip
}
func (c *caseEnv) policy(ip, policy string) {
	c.Helper()
	c.post("/network/policy", M{"ip": ip, "policy": policy})
	c.cleanup("POST", "/network/policy", M{"ip": ip, "policy": "default"})
}
func (c *caseEnv) pause(scope, id string, duration uint64) {
	c.Helper()
	body := M{"scope": scope}
	if id != "" {
		body["id"] = id
	}
	if duration > 0 {
		body["duration_secs"] = duration
	}
	c.post("/protection/pause", body)
	c.cleanup("POST", "/protection/resume", M{"scope": scope, "id": id})
}
func hasAnswer(message *dns.Msg, qt uint16, value string) bool {
	for _, rr := range message.Answer {
		if rr.Header().Rrtype != qt {
			continue
		}
		switch r := rr.(type) {
		case *dns.A:
			if r.A.String() == value {
				return true
			}
		case *dns.AAAA:
			if r.AAAA.String() == value {
				return true
			}
		case *dns.CNAME:
			if strings.EqualFold(strings.TrimSuffix(r.Target, "."), strings.TrimSuffix(value, ".")) {
				return true
			}
		}
	}
	return false
}
func contains(items []string, item string) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}
func escaped(value string) string { return url.QueryEscape(value) }
