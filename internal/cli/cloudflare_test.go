package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"nodekit/internal/httpapi"
	"nodekit/internal/model"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type editBackend struct{ certBackend }

func (b editBackend) Reset(context.Context) error { return nil }

func TestCloudflareCLIEditingAndMenu(t *testing.T) {
	root, err := os.MkdirTemp("", "nk-cf-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	p := makePaths(root, "")
	if err = os.MkdirAll(p.Run, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := p.db()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c, _ := model.New()
	c.Address = "8.8.8.8"
	// The synthetic admin fixture already owns a compatible subscription port;
	// no new bind is needed on hosts also running a production NodeKit instance.
	c.SubscriptionPort = 8443
	if err = db.Update(func(r *store.Record) error { r.Config = c; r.Meter.Upload = 123; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(p.Etc, "runtime.json"), runtimeConfig{Firewall: "manual"}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(p.Run, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: httpapi.Admin(editBackend{certBackend{db}})}
	go server.Serve(ln)
	defer server.Close()
	var out bytes.Buffer
	if err = edit(context.Background(), p, []string{"config", "set", "subscription-mode", "cloudflare"}, &out); err != nil {
		t.Fatal(err)
	}
	r, _ := db.Load()
	if r.Config.SubscriptionMode != "cloudflare" || r.Config.SubscriptionPort != 8443 || r.Meter.Upload != 123 || r.Config.Token != c.Token {
		t.Fatal("mode switch changed unrelated state")
	}
	if !strings.Contains(out.String(), "8443") {
		t.Fatal("port change was not displayed")
	}
	if err = edit(context.Background(), p, []string{"config", "set", "address", "127.0.0.1"}, &out); err == nil {
		t.Fatal("invalid address committed")
	}
	var errOut bytes.Buffer
	menu(context.Background(), p, strings.NewReader("17\n1.1.1.1\n16\ndirect\n0\n"), &out, &errOut)
	r, _ = db.Load()
	if errOut.Len() != 0 || r.Config.Address != "1.1.1.1" || r.Config.EffectiveSubscriptionMode() != "direct" {
		t.Fatal("menu edit failed", errOut.String())
	}
	out.Reset()
	if err = execute(context.Background(), p, []string{"status"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "direct") || !strings.Contains(out.String(), c.Domain) {
		t.Fatal("status lacks mode/address", out.String())
	}
	for _, port := range []int{24446, 8443} {
		t.Run(fmt.Sprintf("legacy-import-%d", port), func(t *testing.T) {
			active := c.Clone()
			active.SubscriptionMode = "cloudflare"
			active.SubscriptionPort = 8443
			active.DisplayMode = "flag-host"
			active.CountryCode = "JP"
			active.Protocols[0].Name = "old override"
			if err := db.Update(func(r *store.Record) error { r.Config = active; return nil }); err != nil {
				t.Fatal(err)
			}
			legacy := c.Clone()
			legacy.SubscriptionPort = port
			legacy.SubscriptionMode = ""
			data, _ := json.Marshal(legacy)
			file := filepath.Join(root, "legacy.json")
			if err := os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := edit(context.Background(), p, []string{"config", "apply", file}, &out); err != nil {
				t.Fatal("legacy import rejected", err)
			}
			record, err := db.Load()
			if err != nil {
				t.Fatal(err)
			}
			if record.Config.EffectiveSubscriptionMode() != "direct" || record.Config.NodeAddress() != c.Domain || record.Config.SubscriptionPort != port {
				t.Fatal("legacy import inherited active mode")
			}
			if record.Config.NodeName(record.Config.Protocols[0]) != "NodeKit-vless" {
				t.Fatal("legacy import inherited new display fields")
			}
		})
	}
}

func TestDomainValidationRespectsMode(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}
	for _, mode := range []string{"", "direct", "cloudflare", "typo"} {
		err := validateDomainAddress(context.Background(), mode, "node.example.com", "8.8.8.8", lookup)
		if (err == nil) != (mode == "cloudflare") {
			t.Fatalf("mode %q: %v", mode, err)
		}
	}
	if err := validateDomainAddress(context.Background(), "direct", "node.example.com", "::ffff:1.1.1.1", lookup); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("DNS offline")
	offline := func(context.Context, string) ([]net.IPAddr, error) { return nil, failure }
	if !errors.Is(validateDomainAddress(context.Background(), "direct", "node.example.com", "8.8.8.8", offline), failure) {
		t.Fatal("lost resolver error")
	}
	if err := validateDomainAddress(context.Background(), "cloudflare", "node.example.com", "8.8.8.8", offline); err != nil {
		t.Fatal("cloudflare requires public lookup", err)
	}
	for _, address := range []string{"", "127.0.0.1"} {
		if validateDomainAddress(context.Background(), "cloudflare", "node.example.com", address, lookup) == nil {
			t.Fatal("accepted invalid address")
		}
	}
}

func TestCloudflareInitDefaultsAndExplicitPorts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		port  int
		valid bool
	}{
		{"default", nil, 8443, true}, {"explicit", []string{"--subscription-port", "2053"}, 2053, true}, {"bad-port", []string{"--subscription-port", "24446"}, 0, false}, {"zero", []string{"--subscription-port", "0"}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			args := []string{"--root", root, "init", "--domain", "node.example.com", "--address", "8.8.8.8", "--subscription-mode", "cloudflare", "--dry-run"}
			args = append(args, tc.extra...)
			var out bytes.Buffer
			code := Run(context.Background(), args, strings.NewReader(""), &out, &out)
			if (code == 0) != tc.valid {
				t.Fatal(code, out.String())
			}
			if !tc.valid {
				return
			}
			b, err := os.ReadFile(filepath.Join(root, "etc/nodekit/bootstrap.json"))
			if err != nil {
				t.Fatal(err)
			}
			var c model.Config
			if err = json.Unmarshal(b, &c); err != nil {
				t.Fatal(err)
			}
			if c.SubscriptionPort != tc.port || c.SubscriptionMode != "cloudflare" {
				t.Fatal("incorrect bootstrap", c.SubscriptionPort, c.SubscriptionMode)
			}
		})
	}
}

func TestCloudflareInitDoesNotSilentlyRewriteImportedPort(t *testing.T) {
	c, _ := model.New()
	c.Address = "8.8.8.8"
	file := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(c)
	os.WriteFile(file, b, 0600)
	for _, override := range []bool{false, true} {
		root := t.TempDir()
		args := []string{"--root", root, "init", "--config", file, "--subscription-mode", "cloudflare", "--dry-run"}
		if override {
			args = append(args, "--subscription-port", "8443")
		}
		var out bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &out)
		if (code == 0) != override {
			t.Fatal(override, code, out.String())
		}
	}
}

func TestCloudflareDomainChangeReachesIssuer(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	db, err := p.db()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c, _ := model.New()
	c.SubscriptionMode = "cloudflare"
	c.SubscriptionPort = 8443
	c.Address = "8.8.8.8"
	if err = db.Update(func(r *store.Record) error { r.Config = c; return nil }); err != nil {
		t.Fatal(err)
	}
	ctl := certificateController{db: db, backend: certBackend{db}, paths: p, runtime: runtimeConfig{TokenFile: "configured"}, issuer: failingIssuer{}}
	if err = ctl.Renew(context.Background(), "new.invalid"); err == nil || !strings.Contains(err.Error(), "provider failure") {
		t.Fatal("orange-cloud domain was rejected before DNS-01", err)
	}
	r, _ := db.Load()
	if r.Config.Domain != c.Domain || r.Certificate.Error == "" {
		t.Fatal("failed issuance changed domain or lost status")
	}
}
