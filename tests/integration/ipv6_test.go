package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"nodekit/internal/core"
	"nodekit/internal/model"
	"nodekit/internal/render"
)

func ipv6CoreFixture(t *testing.T) (string, string, model.Config) {
	t.Helper()
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" {
		t.Skip("set NODEKIT_CORE_BIN to the isolated pinned core")
	}
	if stat, err := os.Stat(bin); err != nil || !stat.Mode().IsRegular() {
		t.Fatalf("isolated core missing: %s (%v)", bin, err)
	}
	// Keep UNIX socket paths below Linux's limit even with a long test TMPDIR.
	dir, err := os.MkdirTemp("", "ip6-core-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless", "ss", "tuic", "hysteria2", "anytls"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	used := map[int]bool{}
	for i := range c.Protocols {
		for {
			port := freePort(t)
			if !used[port] {
				c.Protocols[i].Port = port
				used[port] = true
				break
			}
		}
	}
	for {
		c.SubscriptionPort = freePort(t)
		if !used[c.SubscriptionPort] {
			break
		}
	}
	return bin, dir, c
}

func ipv6LoopbackServer(t *testing.T, c model.Config, paths render.Paths) []byte {
	t.Helper()
	// Model validation intentionally rejects loopback. Render the valid public
	// fixture first, then substitute ONLY the test listener's bind address.
	b, err := render.Server(c, paths)
	if err != nil {
		t.Fatal(err)
	}
	var server map[string]any
	if err = yaml.Unmarshal(b, &server); err != nil {
		t.Fatal(err)
	}
	if server["ipv6"] != false {
		t.Fatal("additional IPv6 nodes changed server resolver policy")
	}
	for _, raw := range server["listeners"].([]any) {
		listener := raw.(map[string]any)
		if listener["listen"] == "0.0.0.0" || listener["listen"] == "::" {
			t.Fatal("feature emitted wildcard listener")
		}
		if listener["listen"] == c.IPv6Nodes.Address {
			listener["listen"] = "::1"
		}
	}
	b, err = yaml.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ipv6WaitHealth(t *testing.T, client *core.Client, c model.Config) {
	t.Helper()
	c = c.Clone()
	c.IPv6Nodes.Address = "::1"
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = client.Health(context.Background(), c); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("explicit-family listeners did not become healthy", err)
}

func ipv6AssertBindings(t *testing.T, c model.Config) {
	t.Helper()
	for _, p := range c.Protocols {
		networks := []string{"tcp"}
		if p.Type == "ss" {
			networks = []string{"tcp", "udp"}
		} else if p.Type == "tuic" || p.Type == "hysteria2" {
			networks = []string{"udp"}
		}
		for _, network := range networks {
			for _, family := range []struct {
				address string
				suffix  string
				present bool
			}{{"127.0.0.1", "4", p.Enabled}, {"::1", "6", c.IPv6ProtocolEnabled(p.Type)}, {"127.0.0.2", "4", false}} {
				address := net.JoinHostPort(family.address, fmt.Sprint(p.Port))
				var closer io.Closer
				var err error
				if network == "tcp" {
					closer, err = net.Listen(network+family.suffix, address)
				} else {
					closer, err = net.ListenPacket(network+family.suffix, address)
				}
				if err == nil {
					closer.Close()
				}
				if (err != nil) != family.present {
					t.Fatalf("%s %s %s: bound=%t, want %t (%v)", p.Type, network, address, err != nil, family.present, err)
				}
			}
		}
	}
}

func TestIPv6FiveProtocolsSamePortForwarding(t *testing.T) {
	bin, dir, c := ipv6CoreFixture(t)
	serverDir := filepath.Join(dir, "server")
	if err := os.MkdirAll(serverDir, 0700); err != nil {
		t.Fatal(err)
	}
	cp, kp, cert := testCert(t, serverDir)
	socket := filepath.Join(dir, "s.sock")
	paths := render.Paths{Socket: socket, Certificate: cp, PrivateKey: kp}
	startCore(t, bin, serverDir, ipv6LoopbackServer(t, c, paths))
	control := &core.Client{Socket: socket, Binary: bin, WorkDir: serverDir}
	ipv6WaitHealth(t, control, c)
	ipv6AssertBindings(t, c)
	if err := control.Health(context.Background(), c); err == nil {
		t.Fatal("loopback sockets satisfied the unassigned public IPv6 address")
	}
	ipv6ForwardSubscriptions(t, bin, dir, c, cert, 10)
	// A normal reload removes ONLY the IPv6 listeners; explicit IPv4 listeners
	// and their original ports survive, without reverting to wildcards.
	c.IPv6Nodes.Enabled = false
	off := ipv6LoopbackServer(t, c, paths)
	offPath := filepath.Join(serverDir, "off.yaml")
	if err := os.WriteFile(offPath, off, 0600); err != nil {
		t.Fatal(err)
	}
	if err := control.Apply(context.Background(), offPath); err != nil {
		t.Fatal(err)
	}
	ipv6WaitHealth(t, control, c)
	ipv6AssertBindings(t, c)
	wantIPv6 := c.Clone()
	wantIPv6.IPv6Nodes.Enabled = true
	wantIPv6.IPv6Nodes.Address = "::1"
	if err := control.Health(context.Background(), wantIPv6); err == nil {
		t.Fatal("remaining IPv4 sockets satisfied disabled IPv6 listeners")
	}
}

func ipv6ForwardSubscriptions(t *testing.T, bin, dir string, c model.Config, cert []byte, wantNodes int) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	defer target.Close()
	udpTarget := udpEcho(t)
	full, err := render.Subscription(c, false)
	if err != nil {
		t.Fatal(err)
	}
	check := &core.Client{Binary: bin, WorkDir: filepath.Join(dir, "subscription-check")}
	if err = check.Check(context.Background(), full); err != nil {
		t.Fatal("full dual-family subscription rejected", err)
	}
	var config map[string]any
	if err = yaml.Unmarshal(full, &config); err != nil {
		t.Fatal(err)
	}
	if config["ipv6"] != true || config["dns"].(map[string]any)["ipv6"] != true {
		t.Fatal("full subscription omitted IPv6 client support")
	}
	b, err := render.Subscription(c, true)
	if err != nil {
		t.Fatal(err)
	}
	var provider map[string]any
	if err = yaml.Unmarshal(b, &provider); err != nil {
		t.Fatal(err)
	}
	proxies := provider["proxies"].([]any)
	if len(proxies) != wantNodes {
		t.Fatalf("want %d selected nodes, got %d", wantNodes, len(proxies))
	}
	block, _ := pem.Decode(cert)
	fingerprint := sha256.Sum256(block.Bytes)
	for i, raw := range proxies {
		node := raw.(map[string]any)
		family := "ipv4"
		if strings.HasSuffix(node["name"].(string), " · IPv6") {
			family = "ipv6"
		}
		t.Run(node["type"].(string)+"-"+family, func(t *testing.T) {
			if family == "ipv6" {
				if node["server"] != "2001:4860:4860::8888" {
					t.Fatal("subscription did not use the selected public IPv6")
				}
				node["server"] = "::1" // TEST ONLY; no public address is assigned.
			} else {
				if node["server"] != "node.example.com" {
					t.Fatal("original subscription address semantics changed")
				}
				node["server"] = "127.0.0.1" // TEST ONLY; the fixture domain has no DNS.
			}
			if node["type"] != "vless" && node["type"] != "ss" {
				if node["skip-cert-verify"] != false {
					t.Fatal("TLS certificate validation disabled")
				}
				node["fingerprint"] = fmt.Sprintf("%x", fingerprint)
			}
			port := freePort(t)
			client := map[string]any{"mixed-port": port, "bind-address": "127.0.0.1", "ipv6": true, "log-level": "warning", "proxies": []any{node}, "rules": []string{"MATCH," + node["name"].(string)}}
			cb, err := yaml.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, filepath.Join(dir, fmt.Sprintf("c%d", i)), cb)
			waitPort(t, port)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			waitProxyReady(t, hc, target.URL)
			payload := bytes.Repeat([]byte("native-family-echo"), 256)
			response, err := hc.Post(target.URL, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || !bytes.Equal(got, payload) {
				t.Fatal("TCP forwarding mismatch", response.StatusCode, err)
			}
			udpRoundTrip(t, port, udpTarget)
			t.Log("TCP and UDP forwarding passed with unchanged credentials and validated TLS")
		})
	}
}

func TestIPv6RealCoreIndependentSelections(t *testing.T) {
	for _, scenario := range []string{"disjoint", "ipv6-only"} {
		t.Run(scenario, func(t *testing.T) {
			bin, dir, c := ipv6CoreFixture(t)
			for i := range c.Protocols {
				c.Protocols[i].Enabled = scenario == "disjoint" && (c.Protocols[i].Type == "vless" || c.Protocols[i].Type == "anytls")
			}
			if scenario == "disjoint" {
				c.IPv6Nodes.Protocols = []string{"ss", "tuic", "hysteria2"}
			}
			cp, kp, cert := testCert(t, dir)
			socket := filepath.Join(dir, "s.sock")
			startCore(t, bin, dir, ipv6LoopbackServer(t, c, render.Paths{Socket: socket, Certificate: cp, PrivateKey: kp}))
			client := &core.Client{Socket: socket}
			ipv6WaitHealth(t, client, c)
			ipv6AssertBindings(t, c)
			wrong := c.Clone()
			wrong.IPv6Nodes.Address = "::1"
			if scenario == "disjoint" {
				wrong.IPv6Nodes.Protocols = []string{"vless"}
			} else {
				wrong.IPv6Nodes.Enabled = false
				wrong.Protocols[0].Enabled = true
			}
			if err := client.Health(context.Background(), wrong); err == nil {
				t.Fatal("unselected family satisfied real-core health")
			}
			ipv6ForwardSubscriptions(t, bin, dir, c, cert, 5)
		})
	}
}
