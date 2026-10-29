package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"nodekit/internal/core"
	"nodekit/internal/model"
	"nodekit/internal/render"
)

func TestRoutingSubscriptionCore(t *testing.T) {
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" {
		t.Skip("set NODEKIT_CORE_BIN to mihomo v1.19.33 for offline routing checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "Mihomo Meta v1.19.33 ") {
		t.Fatalf("routing checks require exact pinned v1.19.33: %v (%s)", err, version)
	}
	t.Log(strings.TrimSpace(string(version)))
	for _, scenario := range []string{"normal", "HK", "name-HK", "no-nodes", "collision", "ipv6", "ipv6-only"} {
		t.Run("original-config/"+scenario, func(t *testing.T) {
			c := routingConfig(t, scenario)
			full, err := render.Subscription(c, false)
			if err != nil {
				t.Fatal(err)
			}
			// The bytes sent to -t are EXACTLY render.Subscription's output:
			// production URLs, DNS, sniffer, credentials, rules and default MMDB.
			check := &core.Client{Binary: bin, WorkDir: t.TempDir()}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := check.Check(ctx, full); err != nil {
				t.Fatal("original emitted full subscription rejected", err)
			}
			t.Log("byte-for-byte emitted full template accepted with cached tiny Geo fixtures")
		})
	}
	for _, scenario := range []string{"normal", "HK", "name-HK", "no-nodes", "collision"} {
		t.Run("runtime/"+scenario, func(t *testing.T) { routingRuntime(t, bin, scenario) })
	}
	t.Run("fake-ip-filter", func(t *testing.T) { routingFakeIPFilter(t, bin) })
}

func routingConfig(t *testing.T, scenario string) model.Config {
	t.Helper()
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.CountryCode = "JP"
	switch scenario {
	case "HK":
		c.CountryCode = "HK"
	case "name-HK":
		for i := range c.Protocols {
			c.Protocols[i].Name = "HK fixture " + c.Protocols[i].Type
		}
	case "no-nodes", "ipv6-only":
		for i := range c.Protocols {
			c.Protocols[i].Enabled = false
		}
	case "collision":
		for i, name := range []string{"▶️ YouTube", "📲 电报信息", "🤖 ChatGPT", "🛑 全球拦截", "🐟 漏网之鱼"} {
			c.Protocols[i].Name = name
		}
	}
	if scenario == "ipv6" || scenario == "ipv6-only" {
		c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless", "anytls"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	}
	return c
}

func routingDocument(t *testing.T, c model.Config) map[string]any {
	t.Helper()
	b, err := render.Subscription(c, false)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// These payloads exercise all three actual provider parsers. Deliberate overlaps
// (YouTube/OpenAI in reject; Gemini in google) prove earlier-rule precedence.
var routingProviderPayloads = map[string][]string{
	"applications": {"DOMAIN,app.fixture.test"}, "private": {"+.private.fixture.test"},
	"reject": {"+.ads.fixture.test", "+.youtube.com", "+.openai.com"},
	"icloud": {"+.icloud.com"}, "apple": {"+.apple.com"}, "google": {"+.google.com"},
	"proxy": {"+.foreign.fixture.test"}, "direct": {"+.cn.fixture.test"},
	"lancidr": {"192.0.2.0/24"}, "cncidr": {"203.0.113.0/24"}, "telegramcidr": {"149.154.160.0/20"},
}

func routingRuntime(t *testing.T, bin, scenario string) {
	c := routingConfig(t, scenario)
	cfg := routingDocument(t, c)
	rules := append([]any(nil), cfg["rules"].([]any)...)
	groups := cfg["proxy-groups"].([]any)
	youtube, telegram, ai, block, final := "▶️ YouTube", "📲 电报信息", "🤖 ChatGPT", "🛑 全球拦截", "🐟 漏网之鱼"
	if scenario == "collision" {
		youtube += " · NodeKit"
		telegram += " · NodeKit"
		ai += " · NodeKit"
		block += " · NodeKit"
		final += " · NodeKit"
	}
	// Only transport is substituted: node/group NAMES and every rule remain
	// intact. Local HTTP CONNECT stubs accept but NEVER dial the requested target.
	sink := routingConnectSink(t)
	sinkURL, _ := url.Parse(sink.URL)
	host, port, _ := net.SplitHostPort(sinkURL.Host)
	for i, raw := range cfg["proxies"].([]any) {
		node := raw.(map[string]any)
		cfg["proxies"].([]any)[i] = map[string]any{"name": node["name"], "type": "http", "server": host, "port": port}
	}
	// Health checks are also loopback-only; retaining public health URLs here
	// would make an otherwise offline routing test contact the Internet.
	for _, raw := range groups {
		group := raw.(map[string]any)
		if _, ok := group["url"]; ok {
			group["url"] = sink.URL + "/generate_204"
		}
	}
	dir := t.TempDir()
	providers := cfg["rule-providers"].(map[string]any)
	for name, raw := range providers {
		p := raw.(map[string]any)
		payload, err := yaml.Marshal(map[string]any{"payload": routingProviderPayloads[name]})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "ruleset", name+".yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		// Keep type, behavior, interval and path; URL points only to the local
		// payload server in case this core elects to refresh a seeded provider.
		p["url"] = sink.URL + "/rules/" + name
	}
	// Domain DIRECT cases terminate at the local holding sink. Nonmatching
	// domains get a reserved non-LAN IP, avoiding all DNS and accidental LAN hits.
	cfg["hosts"] = map[string]any{
		"cn.fixture.test": "127.0.0.1", "app.fixture.test": "127.0.0.1", "private.fixture.test": "127.0.0.1",
		"clash.razord.top": "127.0.0.1", "yacd.haishan.me": "127.0.0.1", "unknown.fixture.test": "198.51.100.8",
	}
	dnsConfig := cfg["dns"].(map[string]any)
	dnsConfig["nameserver"], dnsConfig["default-nameserver"] = []string{"rcode://name_error"}, []string{"127.0.0.1"}
	api, mixed := freePort(t), freePort(t)
	cfg["external-controller"] = fmt.Sprintf("127.0.0.1:%d", api)
	cfg["mixed-port"], cfg["bind-address"], cfg["log-level"] = mixed, "127.0.0.1", "info"
	if !reflect.DeepEqual(cfg["rules"], rules) {
		t.Fatal("runtime fixture changed the emitted rules")
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, dir, b)
	waitPort(t, api)
	waitPort(t, mixed)
	apiURL := fmt.Sprintf("http://127.0.0.1:%d", api)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	routingWaitProviders(t, client, apiURL)
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixed))
	ready := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: time.Second}
	t.Cleanup(ready.CloseIdleConnections)
	waitProxyReady(t, ready, sink.URL) // listeners/providers alone precede tunnel.OnRunning
	proxyLeaf, aiLeaf := "", ""
	if scenario == "no-nodes" {
		proxyLeaf = "REJECT"
	}
	if scenario == "HK" || scenario == "name-HK" || scenario == "no-nodes" {
		aiLeaf = "REJECT"
	}
	_, targetPort, _ := net.SplitHostPort(sinkURL.Host)
	cases := []struct{ name, target, rule, payload, group, leaf string }{
		{"youtube", "www.youtube.com", "GeoSite", "youtube", youtube, proxyLeaf},
		{"openai", "api.openai.com", "OR", "", ai, aiLeaf},
		{"gemini", "gemini.google.com", "OR", "", ai, aiLeaf},
		{"bard", "bard.google.com", "OR", "", ai, aiLeaf},
		{"ads", "ads.fixture.test", "RuleSet", "reject", block, "REJECT"},
		{"icloud", "www.icloud.com", "RuleSet", "icloud", "节点选择", proxyLeaf},
		{"apple", "www.apple.com", "RuleSet", "apple", "节点选择", proxyLeaf},
		{"google", "www.google.com", "RuleSet", "google", "节点选择", proxyLeaf},
		{"foreign", "foreign.fixture.test", "RuleSet", "proxy", "节点选择", proxyLeaf},
		{"cn", "cn.fixture.test", "RuleSet", "direct", "DIRECT", "DIRECT"},
		{"application", "app.fixture.test", "RuleSet", "applications", "DIRECT", "DIRECT"},
		{"private", "private.fixture.test", "RuleSet", "private", "DIRECT", "DIRECT"},
		{"dashboard", "clash.razord.top", "Domain", "clash.razord.top", "DIRECT", "DIRECT"},
		{"loopback", "127.0.0.1", "IPCIDR", "127.0.0.0/8", "DIRECT", "DIRECT"},
		{"geoip-lan", "0.0.0.0", "GeoIP", "lan", "DIRECT", "DIRECT"},
		{"telegram", "149.154.167.51", "RuleSet", "telegramcidr", telegram, proxyLeaf},
		{"unknown", "unknown.fixture.test", "Match", "", final, proxyLeaf},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			routingAssertMatch(t, client, apiURL, mixed, dir, net.JoinHostPort(tc.target, targetPort), tc.rule, tc.payload, tc.group, tc.leaf)
		})
	}
}

func routingConnectSink(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/rules/") {
			payload, ok := routingProviderPayloads[strings.TrimPrefix(r.URL.Path, "/rules/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = yaml.NewEncoder(w).Encode(map[string]any{"payload": payload})
			return
		}
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		<-done
	}))
	t.Cleanup(func() { close(done); s.Close() })
	return s
}

func routingGet(client *http.Client, endpoint string, result any) error {
	r, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("core API status %d", r.StatusCode)
	}
	return json.NewDecoder(r.Body).Decode(result)
}

func routingWaitProviders(t *testing.T, client *http.Client, api string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var result struct {
		Providers map[string]struct {
			RuleCount int `json:"ruleCount"`
		} `json:"providers"`
	}
	for time.Now().Before(deadline) {
		if routingGet(client, api+"/providers/rules", &result) == nil && len(result.Providers) == 11 {
			ready := true
			for name, payload := range routingProviderPayloads {
				if result.Providers[name].RuleCount != len(payload) {
					ready = false
				}
			}
			if ready {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("providers did not initialize: %+v", result)
}

func routingAssertMatch(t *testing.T, client *http.Client, api string, port int, dir, target, rule, payload, group, leaf string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	sourcePort := fmt.Sprint(conn.LocalAddr().(*net.TCPAddr).Port)
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("local CONNECT failed: %v", err)
	}
	// Trigger forwarding even on cores that wait for the first payload byte.
	_, _ = conn.Write([]byte("routing-characterization\n"))
	deadline := time.Now().Add(5 * time.Second)
	var result struct {
		Connections []struct {
			Metadata struct {
				SourcePort string `json:"sourcePort"`
			} `json:"metadata"`
			Rule        string   `json:"rule"`
			RulePayload string   `json:"rulePayload"`
			Chains      []string `json:"chains"`
		} `json:"connections"`
	}
	for time.Now().Before(deadline) {
		if leaf == "REJECT" {
			// Rejections disappear too quickly for /connections. This is the
			// actual tunnel match log for THIS source socket, not a rule listing.
			log, _ := os.ReadFile(filepath.Join(dir, "core.log"))
			for _, line := range strings.Split(string(log), "\n") {
				if strings.Contains(line, "127.0.0.1:"+sourcePort+" --> "+target) && strings.Contains(line, " match "+rule) && strings.Contains(line, "using "+group+"[REJECT]") {
					if payload != "" && !strings.Contains(line, rule+"("+payload+")") {
						t.Fatal("wrong rejecting rule", line)
					}
					t.Logf("actual core match: %s -> %s / %s -> REJECT", target, rule, group)
					return
				}
			}
		} else if routingGet(client, api+"/connections", &result) == nil {
			for _, match := range result.Connections {
				if match.Metadata.SourcePort != sourcePort {
					continue
				}
				if match.Rule != rule || (payload != "" && match.RulePayload != payload) {
					t.Fatalf("wrong live rule: %+v", match)
				}
				if !containsRoutingChain(match.Chains, group) || (leaf != "" && !containsRoutingChain(match.Chains, leaf)) || containsRoutingChain(match.Chains, "REJECT") || (group != "DIRECT" && containsRoutingChain(match.Chains, "DIRECT")) {
					t.Fatalf("wrong live chain for %s: %+v", target, match)
				}
				t.Logf("live core connection: %s -> %s(%s) -> %v", target, match.Rule, match.RulePayload, match.Chains)
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no actual %s/%s match via %s for source port %s", rule, payload, group, sourcePort)
}

func containsRoutingChain(chains []string, want string) bool {
	for _, chain := range chains {
		if chain == want {
			return true
		}
	}
	return false
}

func routingFakeIPFilter(t *testing.T, bin string) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		res := new(dns.Msg)
		res.SetReply(req)
		for _, q := range req.Question {
			if q.Qtype == dns.TypeA {
				res.Answer = append(res.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.7")})
			}
		}
		_ = w.WriteMsg(res)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	for _, control := range []bool{false, true} {
		name := "reference"
		if control {
			name = "empty-filter-control"
		}
		t.Run(name, func(t *testing.T) {
			cfg := routingDocument(t, routingConfig(t, "normal"))
			d := cfg["dns"].(map[string]any)
			if control {
				d["fake-ip-filter"] = []string{}
			}
			port := freePort(t)
			d["listen"] = fmt.Sprintf("127.0.0.1:%d", port)
			d["nameserver"], d["default-nameserver"] = []string{packet.LocalAddr().String()}, []string{"127.0.0.1"}
			// DNS-only characterization: no proxies, remote providers or health
			// checks; the original filter/mode/range are retained in reference.
			minimal := map[string]any{"dns": d, "rules": []string{"MATCH,REJECT"}}
			b, err := yaml.Marshal(minimal)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, t.TempDir(), b)
			query := &dns.Client{Timeout: time.Second}
			for _, item := range []struct {
				domain string
				real   bool
			}{{"single", true}, {"ordinary.example", false}, {"nested.ordinary.example", false}, {"printer.lan", true}, {"a.b.lan", true}, {"host.local", true}} {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(item.domain), dns.TypeA)
				var reply *dns.Msg
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					reply, _, err = query.Exchange(msg, fmt.Sprintf("127.0.0.1:%d", port))
					if err == nil && len(reply.Answer) > 0 {
						break
					}
					time.Sleep(25 * time.Millisecond)
				}
				if err != nil || reply == nil || len(reply.Answer) != 1 {
					t.Fatalf("DNS %s: %v (%v)", item.domain, err, reply)
				}
				a, ok := reply.Answer[0].(*dns.A)
				if !ok {
					t.Fatalf("DNS not A: %v", reply)
				}
				ip, _ := netip.AddrFromSlice(a.A)
				fake := netip.MustParsePrefix("198.18.0.0/16").Contains(ip.Unmap())
				wantReal := item.real && !control
				if (wantReal && a.A.String() != "203.0.113.7") || (!wantReal && !fake) {
					t.Fatalf("DNS %s = %s, want real=%t", item.domain, a.A, wantReal)
				}
				t.Logf("%s => %s (real=%t)", item.domain, a.A, wantReal)
			}
		})
	}
}
