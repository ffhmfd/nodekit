package integration

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRejectWrongCredentials(t *testing.T) {
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" {
		t.Skip("set NODEKIT_CORE_BIN")
	}
	dir := t.TempDir()
	c, _ := model.New()
	wrong, _ := model.New()
	for i := range c.Protocols {
		c.Protocols[i].Port = freePort(t)
	}
	c.SubscriptionPort = freePort(t)
	cp, kp, cert := testCert(t, dir)
	server, e := render.Server(c, render.Paths{Socket: filepath.Join(dir, "s.sock"), WorkDir: dir, Certificate: cp, PrivateKey: kp})
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, dir, server)
	waitPort(t, c.Protocols[0].Port)
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "must-not-be-reached") }))
	defer target.Close()
	b, _ := render.Subscription(c, true)
	var subs map[string]any
	if e = yaml.Unmarshal(b, &subs); e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(cert)
	sum := sha256.Sum256(block.Bytes)
	for i, raw := range subs["proxies"].([]any) {
		p := raw.(map[string]any)
		t.Run(c.Protocols[i].Type, func(t *testing.T) {
			p["server"] = "127.0.0.1"
			if p["type"] == "vless" {
				p["uuid"] = wrong.Protocols[i].UUID
			} else {
				p["password"] = wrong.Protocols[i].Password
			}
			if p["type"] != "vless" && p["type"] != "ss" {
				p["fingerprint"] = fmt.Sprintf("%x", sum)
			}
			port := freePort(t)
			client, e := yaml.Marshal(map[string]any{"mixed-port": port, "bind-address": "127.0.0.1", "log-level": "warning", "proxies": []any{p}, "rules": []string{"MATCH," + p["name"].(string)}})
			if e != nil {
				t.Fatal(e)
			}
			startCore(t, bin, t.TempDir(), client)
			waitPort(t, port)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			res, e := hc.Get(target.URL)
			if e == nil {
				res.Body.Close()
				if res.StatusCode == 200 {
					t.Fatal("invalid credentials accepted")
				}
			}
			if hits.Load() != 0 {
				t.Fatal("invalid credentials reached origin")
			}
		})
	}
}
