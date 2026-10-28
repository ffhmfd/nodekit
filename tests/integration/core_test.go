package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nodekit/internal/core"
	"nodekit/internal/model"
	"nodekit/internal/render"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := l.Addr().(*net.TCPAddr).Port
		u, e := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", p))
		_ = l.Close()
		if e == nil {
			_ = u.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}
func testCert(t *testing.T, dir string) (string, string, []byte) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node.example.com"}, DNSNames: []string{"node.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if e = os.WriteFile(cp, cert, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); e != nil {
		t.Fatal(e)
	}
	return cp, kp, cert
}
func startCore(t *testing.T, bin, dir string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if e := os.WriteFile(cfg, b, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if o, e := exec.CommandContext(ctx, bin, "-d", dir, "-f", cfg, "-t").CombinedOutput(); e != nil {
		t.Fatalf("configuration invalid: %v\n%s", e, o)
	}
	log, e := os.Create(filepath.Join(dir, "core.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(bin, "-d", dir, "-f", cfg)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(dir, "core.log"))
			t.Logf("core log: %s", b)
		}
	})
}
func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("core did not open expected port")
}
func totals(t *testing.T, socket string) (int64, int64) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	r, e := c.Get("http://core/connections")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	var v struct {
		Upload   int64 `json:"uploadTotal"`
		Download int64 `json:"downloadTotal"`
	}
	if e = json.NewDecoder(r.Body).Decode(&v); e != nil {
		t.Fatal(e)
	}
	return v.Upload, v.Download
}

// Mihomo opens listeners before ApplyConfig calls tunnel.OnRunning. A TCP
// accept alone is therefore not a readiness signal for proxy traffic.
func waitProxyReady(t *testing.T, client *http.Client, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for attempts := 1; ; attempts++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err == nil {
			_, readErr := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == 200 && readErr == nil {
				if attempts > 1 {
					t.Logf("proxy forwarding ready after %d startup probes", attempts)
				}
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("proxy forwarding never became ready", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestFiveProtocols(t *testing.T) {
	testFiveProtocols(t, false)
}

func TestCloudflareFiveProtocols(t *testing.T) {
	testFiveProtocols(t, true)
}

func testFiveProtocols(t *testing.T, cloudflare bool) {
	bin := os.Getenv("NODEKIT_CORE_BIN")
	if bin == "" {
		t.Skip("set NODEKIT_CORE_BIN to run isolated real-kernel tests")
	}
	dir := t.TempDir()
	c, e := model.New()
	if e != nil {
		t.Fatal(e)
	}
	for i := range c.Protocols {
		c.Protocols[i].Port = freePort(t)
	}
	c.SubscriptionPort = freePort(t)
	if cloudflare {
		c.SubscriptionMode = "cloudflare"
		c.SubscriptionPort = 8443
		c.Address = "8.8.8.8"
	}
	serverDir := filepath.Join(dir, "server")
	if e = os.MkdirAll(serverDir, 0700); e != nil {
		t.Fatal(e)
	}
	cp, kp, cert := testCert(t, serverDir)
	socket := filepath.Join(dir, "s.sock")
	server, e := render.Server(c, render.Paths{Socket: socket, Certificate: cp, PrivateKey: kp})
	if e != nil {
		t.Fatal(e)
	}
	startCore(t, bin, serverDir, server)
	waitPort(t, c.Protocols[0].Port)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read failed", 500)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer target.Close()
	udpTarget := udpEcho(t)
	b, e := render.Subscription(c, true)
	if e != nil {
		t.Fatal(e)
	}
	if cloudflare {
		full, err := render.Subscription(c, false)
		if err != nil {
			t.Fatal(err)
		}
		check := &core.Client{Binary: bin, WorkDir: filepath.Join(dir, "full-subscription-check")}
		if err = check.Check(context.Background(), full); err != nil {
			t.Fatal("complete subscription rejected by core", err)
		}
	}
	var subs map[string]any
	if e = yaml.Unmarshal(b, &subs); e != nil {
		t.Fatal(e)
	}
	for i, raw := range subs["proxies"].([]any) {
		n := raw.(map[string]any)
		if cloudflare && n["server"] != "8.8.8.8" {
			t.Fatal("cloudflare renderer did not emit the configured IP")
		}
		t.Run(c.Protocols[i].Type, func(t *testing.T) {
			n["server"] = "127.0.0.1"
			if c.Protocols[i].Type != "vless" && c.Protocols[i].Type != "ss" {
				block, _ := pem.Decode(cert)
				sum := sha256.Sum256(block.Bytes)
				n["fingerprint"] = fmt.Sprintf("%x", sum)
			}
			port := freePort(t)
			client := map[string]any{"mixed-port": port, "bind-address": "127.0.0.1", "log-level": "warning", "proxies": []any{n}, "rules": []string{"MATCH," + n["name"].(string)}}
			cb, e := yaml.Marshal(client)
			if e != nil {
				t.Fatal(e)
			}
			startCore(t, bin, filepath.Join(dir, c.Protocols[i].Type), cb)
			waitPort(t, port)
			u, d := totals(t, socket)
			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr, Timeout: 20 * time.Second}
			waitProxyReady(t, hc, target.URL)
			body := bytes.Repeat([]byte("x"), 1024)
			for j := 0; j < 20; j++ {
				r, e := hc.Post(target.URL, "application/octet-stream", bytes.NewReader(body))
				if e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(r.Body)
				_ = r.Body.Close()
				if e != nil || r.StatusCode != 200 || !bytes.Equal(got, body) {
					t.Fatalf("transfer failed status=%d bytes=%d err=%v", r.StatusCode, len(got), e)
				}
			}
			u2, d2 := totals(t, socket)
			if u2-u < 20*1024 || d2-d < 20*1024 {
				t.Fatalf("short connections missing: upload=%d download=%d", u2-u, d2-d)
			}
			t.Logf("20 short TCP streams: upload=%d download=%d", u2-u, d2-d)
			udpRoundTrip(t, port, udpTarget)
		})
	}
	control := &core.Client{Socket: socket, WorkDir: serverDir, Binary: bin}
	if e = control.Health(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	before, e := control.Snapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = control.Apply(context.Background(), filepath.Join(serverDir, "config.yaml")); e != nil {
		t.Fatal(e)
	}
	after, e := control.Snapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("reload counters: before=%d/%d after=%d/%d", before.Upload, before.Download, after.Upload, after.Download)
	if e = control.Health(context.Background(), c); e != nil {
		t.Fatal(e)
	}
}
