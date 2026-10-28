package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type crossFixture struct {
	Config                         model.Config
	Fingerprint, HTTP, UDP, Server string
}

func TestCrossHostServer(t *testing.T) {
	export := os.Getenv("NODEKIT_CROSS_EXPORT")
	if export == "" {
		t.Skip("cross host server mode not enabled")
	}
	bin := os.Getenv("NODEKIT_CORE_BIN")
	dir := t.TempDir()
	cfg, _ := model.New()
	for i := range cfg.Protocols {
		cfg.Protocols[i].Port = freePort(t)
	}
	cfg.SubscriptionPort = freePort(t)
	if os.Getenv("NODEKIT_CROSS_MODE") == "cloudflare" {
		cfg.SubscriptionMode = "cloudflare"
		cfg.SubscriptionPort = 8443
		cfg.Address = os.Getenv("NODEKIT_CROSS_ADDRESS")
	}
	cp, kp, cert := testCert(t, dir)
	b, e := render.Server(cfg, render.Paths{Socket: filepath.Join(dir, "c.sock"), WorkDir: dir, Certificate: cp, PrivateKey: kp})
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, dir, b)
	waitPort(t, cfg.Protocols[0].Port)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read failed", 500)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer target.Close()
	block, _ := pem.Decode(cert)
	hash := sha256.Sum256(block.Bytes)
	fixture := crossFixture{cfg, fmt.Sprintf("%x", hash), target.URL, udpEcho(t), os.Getenv("NODEKIT_CROSS_ADDRESS")}
	b, e = json.Marshal(fixture)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(export, b, 0600); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(export)
	defer os.Remove(export + ".stop")
	t.Log("cross-host test server ready; credentials written only to private fixture")
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		if _, e = os.Stat(export + ".stop"); e == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("cross-host test deadline exceeded")
}
func TestCrossHostClient(t *testing.T) {
	path := os.Getenv("NODEKIT_CROSS_IMPORT")
	if path == "" {
		t.Skip("cross host client mode not enabled")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var f crossFixture
	if e = json.Unmarshal(data, &f); e != nil {
		t.Fatal(e)
	}
	b, e := render.Subscription(f.Config, true)
	if e != nil {
		t.Fatal(e)
	}
	var subs map[string]any
	if e = yaml.Unmarshal(b, &subs); e != nil {
		t.Fatal(e)
	}
	for i, raw := range subs["proxies"].([]any) {
		p := raw.(map[string]any)
		t.Run(f.Config.Protocols[i].Type, func(t *testing.T) {
			if f.Config.EffectiveSubscriptionMode() == "cloudflare" {
				if p["server"] != f.Server {
					t.Fatal("generated node does not dial origin IP")
				}
			} else {
				p["server"] = f.Server
			}
			if p["type"] != "vless" && p["type"] != "ss" {
				p["fingerprint"] = f.Fingerprint
			}
			port := freePort(t)
			cfg := map[string]any{"mixed-port": port, "bind-address": "127.0.0.1", "log-level": "warning", "proxies": []any{p}, "rules": []string{"MATCH," + p["name"].(string)}}
			yamlConfig, e := yaml.Marshal(cfg)
			if e != nil {
				t.Fatal(e)
			}
			startCore(t, os.Getenv("NODEKIT_CORE_BIN"), t.TempDir(), yamlConfig)
			waitPort(t, port)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			waitProxyReady(t, hc, f.HTTP)
			want := bytes.Repeat([]byte("cross-host-nodekit"), 128)
			res, e := hc.Post(f.HTTP, "application/octet-stream", bytes.NewReader(want))
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(res.Body)
			res.Body.Close()
			if e != nil || res.StatusCode != 200 || !bytes.Equal(want, got) {
				t.Fatalf("cross-host TCP failed status=%d want=%d got=%d prefix=%q err=%v", res.StatusCode, len(want), len(got), got[:min(100, len(got))], e)
			}
			udpRoundTrip(t, port, f.UDP)
		})
	}
}
