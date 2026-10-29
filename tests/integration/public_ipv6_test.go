package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nodekit/internal/cli"
	"nodekit/internal/core"
	"nodekit/internal/httpapi"
	"nodekit/internal/manager"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt in with an address already assigned to this host. This validates native
// public-address binds and protocol traffic, not an external network's ingress
// policy. No address, interface, route or firewall is created by this test.
func TestPublicIPv6ManagerLifecycle(t *testing.T) {
	address := os.Getenv("NODEKIT_PUBLIC_IPV6")
	if address == "" {
		t.Skip("explicit assigned public IPv6 required")
	}
	assigned := false
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range interfaces {
		ip, _, err := net.ParseCIDR(candidate.String())
		if err == nil && ip.String() == address {
			assigned = true
		}
	}
	if !assigned {
		t.Fatal("public IPv6 test address is not already assigned")
	}
	bin, dir, old := ipv6CoreFixture(t)
	old.IPv6Nodes = nil
	cp, kp, certificate := testCert(t, dir)
	socket := filepath.Join(dir, "s.sock")
	paths := render.Paths{WorkDir: dir, Socket: socket, Certificate: cp, PrivateKey: kp}
	server, err := render.Server(old, paths)
	if err != nil {
		t.Fatal(err)
	}
	startCore(t, bin, dir, server)
	waitPort(t, old.Protocols[0].Port)
	db, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Update(func(r *store.Record) error { r.Config = old; return nil }); err != nil {
		t.Fatal(err)
	}
	control := &core.Client{Socket: socket, Binary: bin, WorkDir: dir}
	mgr, err := manager.New(db, control, nil, paths)
	if err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "host")
	for _, subdir := range []string{"etc/nodekit", "run/nodekit"} {
		if err := os.MkdirAll(filepath.Join(host, subdir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(host, "etc/nodekit/runtime.json"), []byte(`{"firewall":"manual"}`), 0600); err != nil {
		t.Fatal(err)
	}
	adminSocket, err := net.Listen("unix", filepath.Join(host, "run/nodekit/admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	admin := &http.Server{Handler: httpapi.Admin(mgr)}
	go admin.Serve(adminSocket)
	t.Cleanup(func() { admin.Close() })
	var output bytes.Buffer
	if code := cli.Run(context.Background(), []string{"--root", host, "ipv6", "configure", "--address", address, "--protocols", "vless,ss,tuic,hy2,anytls"}, strings.NewReader(""), &output, &output); code != 0 {
		t.Fatal("CLI wildcard to public-address transition", code, output.String())
	}
	r, err := db.Load()
	if err != nil || r.Config.Token != old.Token || r.Operation != nil {
		t.Fatal("published transition changed token/journal", err)
	}
	if err := control.Health(context.Background(), r.Config); err != nil {
		t.Fatal("public-address endpoint health", err)
	}
	publicIPv6Forward(t, bin, dir, r.Config, certificate)
	// View intentionally serves a snapshot younger than five seconds; force the
	// normal sampler API rather than assuming fast test traffic already landed.
	if err := mgr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	usage, err := mgr.View(context.Background())
	if err != nil || usage.Meter.Upload == 0 || usage.Meter.Download == 0 {
		t.Fatal("dual-family traffic not sampled", err)
	}
	output.Reset()
	if code := cli.Run(context.Background(), []string{"--root", host, "ipv6", "configure", "--address", address, "--protocols", "vless,hy2"}, strings.NewReader(""), &output, &output); code != 0 {
		t.Fatal("independent public IPv6 selection", code, output.String())
	}
	r, err = db.Load()
	if err != nil || !r.Config.IPv6ProtocolEnabled("vless") || !r.Config.IPv6ProtocolEnabled("hysteria2") || r.Config.IPv6ProtocolEnabled("ss") || r.Config.IPv6ProtocolEnabled("tuic") || r.Config.IPv6ProtocolEnabled("anytls") {
		t.Fatal("public IPv6 protocols followed original Enabled flags", err)
	}
	for _, p := range r.Config.Protocols {
		if !p.Enabled {
			t.Fatal("IPv6 selection disabled an original IPv4 protocol")
		}
	}
	provider, err := render.Subscription(r.Config, true)
	if err != nil {
		t.Fatal(err)
	}
	var selected map[string]any
	if err := yaml.Unmarshal(provider, &selected); err != nil {
		t.Fatal(err)
	}
	if len(selected["proxies"].([]any)) != 7 {
		t.Fatal("selected public IPv6 subscription has wrong node count")
	}
	if err := control.Health(context.Background(), r.Config); err != nil {
		t.Fatal("selected public IPv6 endpoint health", err)
	}
	if code := cli.Run(context.Background(), []string{"--root", host, "ipv6", "disable"}, strings.NewReader(""), &output, &output); code != 0 {
		t.Fatal("CLI IPv6 disable", code, output.String())
	}
	r, err = db.Load()
	if err != nil || r.Config.IPv6Nodes == nil || r.Config.HasIPv6Nodes() || r.Config.Token != old.Token {
		t.Fatal("disable lost settings", err)
	}
	if err := control.Health(context.Background(), r.Config); err != nil {
		t.Fatal("IPv4 listeners lost after disable", err)
	}
	for _, p := range r.Config.Protocols {
		networks := []string{"tcp6"}
		if p.Type == "ss" {
			networks = []string{"tcp6", "udp6"}
		}
		if p.Type == "tuic" || p.Type == "hysteria2" {
			networks = []string{"udp6"}
		}
		for _, network := range networks {
			endpoint := net.JoinHostPort(address, fmt.Sprint(p.Port))
			var closer io.Closer
			var err error
			if network == "tcp6" {
				closer, err = net.Listen(network, endpoint)
			} else {
				closer, err = net.ListenPacket(network, endpoint)
			}
			if err != nil {
				t.Fatal("disabled IPv6 listener remained", p.Type, network, err)
			}
			closer.Close()
		}
	}
	if usage.Meter.Upload > r.Meter.Upload || usage.Meter.Download > r.Meter.Download {
		t.Fatal("disable reset usage")
	}
	t.Log("all five protocols forwarded via the assigned public IPv6 and IPv4; transactional enable/disable and usage preserved; no network configuration modified")
}

func publicIPv6Forward(t *testing.T, bin, dir string, config model.Config, certificate []byte) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	defer target.Close()
	udpTarget := udpEcho(t)
	b, err := render.Subscription(config, true)
	if err != nil {
		t.Fatal(err)
	}
	var provider map[string]any
	if err := yaml.Unmarshal(b, &provider); err != nil {
		t.Fatal(err)
	}
	proxies := provider["proxies"].([]any)
	if len(proxies) != 10 {
		t.Fatal("subscription missing paired nodes", len(proxies))
	}
	block, _ := pem.Decode(certificate)
	fingerprint := sha256.Sum256(block.Bytes)
	for i, raw := range proxies {
		node := raw.(map[string]any)
		t.Run(node["name"].(string), func(t *testing.T) {
			if strings.HasSuffix(node["name"].(string), " · IPv6") {
				if node["server"] != config.IPv6Nodes.Address {
					t.Fatal("public IPv6 subscription address changed")
				}
			} else {
				node["server"] = "127.0.0.1"
			}
			if node["type"] != "vless" && node["type"] != "ss" {
				if node["skip-cert-verify"] != false {
					t.Fatal("certificate verification disabled")
				}
				node["fingerprint"] = fmt.Sprintf("%x", fingerprint)
			}
			port := freePort(t)
			client := map[string]any{"mixed-port": port, "bind-address": "127.0.0.1", "ipv6": true, "log-level": "warning", "proxies": []any{node}, "rules": []string{"MATCH," + node["name"].(string)}}
			b, err := yaml.Marshal(client)
			if err != nil {
				t.Fatal(err)
			}
			startCore(t, bin, filepath.Join(dir, fmt.Sprintf("pub-c%d", i)), b)
			waitPort(t, port)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 15 * time.Second}
			waitProxyReady(t, httpClient, target.URL)
			payload := bytes.Repeat([]byte("public-ipv6-native-test"), 128)
			response, err := httpClient.Post(target.URL, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || !bytes.Equal(got, payload) {
				t.Fatal("public-address forwarding mismatch", err)
			}
			udpRoundTrip(t, port, udpTarget)
		})
	}
}
