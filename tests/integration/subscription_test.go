package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	urlpkg "net/url"
	"nodekit/internal/cli"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPortableLifecycle(t *testing.T) {
	testPortableLifecycle(t, false)
}

func TestCloudflarePortableLifecycle(t *testing.T) {
	testPortableLifecycle(t, true)
}

func availableCloudflarePort(t *testing.T, exclude int) int {
	t.Helper()
	for _, port := range []int{8443, 2053, 2083, 2087, 2096} {
		if port == exclude {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	t.Fatal("no free cloudflare test port")
	return 0
}

func testPortableLifecycle(t *testing.T, cloudflare bool) {
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" {
		t.Skip("set NODEKIT_CORE_BIN")
	}
	root := t.TempDir()
	cfg, _ := model.New()
	for i := range cfg.Protocols {
		cfg.Protocols[i].Port = freePort(t)
	}
	cfg.SubscriptionPort = freePort(t)
	if cloudflare {
		cfg.SubscriptionMode = "cloudflare"
		cfg.Address = "8.8.8.8"
		cfg.SubscriptionPort = availableCloudflarePort(t, 0)
	}
	cp, kp, trust := testCert(t, root)
	input := filepath.Join(root, "input.json")
	b, _ := json.Marshal(cfg)
	if e := os.WriteFile(input, b, 0600); e != nil {
		t.Fatal(e)
	}
	prefix := []string{"--root", root, "--core-bin", bin}
	var out, stderr bytes.Buffer
	initArgs := append(append([]string{}, prefix...), "init", "--config", input, "--certificate", cp, "--key", kp, "--no-service")
	if code := cli.Run(context.Background(), initArgs, bytes.NewReader(nil), &out, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	data := filepath.Join(root, "var/lib/nodekit")
	b, e := os.ReadFile(filepath.Join(data, "active.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, data, b)
	waitPort(t, cfg.Protocols[0].Port)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, append(append([]string{}, prefix...), "serve"), bytes.NewReader(nil), io.Discard, io.Discard)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("manager did not stop")
		}
	}()
	waitPort(t, cfg.SubscriptionPort)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(trust)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: cfg.Domain}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://127.0.0.1:%d/s/%s/config.yaml", cfg.SubscriptionPort, cfg.Token)
	res, e := hc.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "proxy-groups:") {
		t.Fatal("invalid HTTPS subscription", res.StatusCode)
	}
	if cloudflare {
		origin, _ := urlpkg.Parse(url)
		origin.Path = ""
		reverse := httputil.NewSingleHostReverseProxy(origin)
		reverse.Transport = tr
		edge := httptest.NewTLSServer(reverse)
		defer edge.Close()
		for _, path := range []string{"/s/" + cfg.Token + "/config.yaml", "/s/" + cfg.Token + "/proxies.yaml", "/s/bad/config.yaml"} {
			r, err := edge.Client().Get(edge.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if strings.Contains(path, "/bad/") {
				if r.StatusCode != 404 {
					t.Fatal("invalid token accepted")
				}
				continue
			}
			if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Subscription-Userinfo") == "" || strings.Count(string(payload), "server: 8.8.8.8") != 5 {
				t.Fatal("simulated edge changed subscription", r.StatusCode, r.Header)
			}
		}
	}
	for _, args := range [][]string{{"config", "set", "quota", "1GB"}, {"config", "set", "expiry", "2020-01-01 08:00"}, {"usage", "reset"}} {
		stderr.Reset()
		if code := cli.Run(context.Background(), append(append([]string{}, prefix...), args...), bytes.NewReader(nil), io.Discard, &stderr); code != 0 {
			t.Fatal(args, stderr.String())
		}
	}
	res, e = hc.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Subscription-Userinfo"), "total=1000000000") {
		t.Fatal("expired quota must remain usable", res.Header)
	}
	db, e := store.Open(filepath.Join(data, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := db.Load()
	db.Close()
	if e != nil || r.Config.Revision != 3 || r.Meter.Upload != 0 {
		t.Fatal("configuration/usage did not persist", r.Config.Revision, r.Meter.Upload, e)
	}
	newPort := freePort(t)
	if cloudflare {
		newPort = availableCloudflarePort(t, cfg.SubscriptionPort)
		blocked, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", newPort))
		if err != nil {
			t.Fatal(err)
		}
		stderr.Reset()
		code := cli.Run(context.Background(), append(append([]string{}, prefix...), "config", "set", "subscription-port", fmt.Sprint(newPort)), bytes.NewReader(nil), io.Discard, &stderr)
		blocked.Close()
		if code == 0 {
			t.Fatal("occupied port was committed")
		}
		db, err := store.Open(filepath.Join(data, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		record, err := db.Load()
		db.Close()
		if err != nil || record.Config.Revision != 3 || record.Config.SubscriptionPort != cfg.SubscriptionPort {
			t.Fatal("failed switch changed revision")
		}
		r, err := hc.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal("old listener lost after failed change")
		}
	}
	stderr.Reset()
	if code := cli.Run(context.Background(), append(append([]string{}, prefix...), "config", "set", "subscription-port", fmt.Sprint(newPort)), bytes.NewReader(nil), io.Discard, &stderr); code != 0 {
		t.Fatal("live port change", stderr.String())
	}
	res, e = hc.Get(fmt.Sprintf("https://127.0.0.1:%d/s/%s/config.yaml", newPort, cfg.Token))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("new subscription listener unavailable")
	}
}
