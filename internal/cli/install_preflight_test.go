package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"nodekit/internal/cloudflare"
	"nodekit/internal/httpapi"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"nodekit/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanceledFirewallPreflightPreservesCancellation(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	c, _ := model.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkInstallFirewall(ctx, c, "auto"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation became unsupported firewall error: %v", err)
	}
}

func TestStaleSetupResumeDoesNotDowngradeReadyInstallation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("setup requires root")
	}
	p := makePaths(t.TempDir(), "")
	for _, dir := range []string{p.Etc, p.Opt, p.Data} {
		if err := platform.Claim(dir); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := model.New()
	c.Domain, c.Address = "node.example.com", "8.8.8.8"
	if err := writeJSON(filepath.Join(p.Etc, "setup.json"), setupInput{Config: c, Firewall: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Data, "state.db"), []byte("already published"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveHost(p, hostManifest{InitPhase: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := saveInstallProgress(p, "完成", true); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(p.Etc, "install-progress.json"))
	var out bytes.Buffer
	_ = setupCommand(context.Background(), p, []string{"--resume", "--firewall", "manual"}, strings.NewReader(""), &out)
	after, _ := os.ReadFile(filepath.Join(p.Etc, "install-progress.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("stale wizard downgraded completed installation")
	}
	if _, err := os.Stat(filepath.Join(p.Etc, "setup-config.json")); !os.IsNotExist(err) {
		t.Fatal("stale draft wrote setup configuration", err)
	}
}

func TestFailedCertificateAndCoreStagesSurviveMenuQuery(t *testing.T) {
	for _, coreFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "certificate", true: "core"}[coreFailure], func(t *testing.T) {
			p := makePaths(t.TempDir(), "")
			cp, kp := filepath.Join(p.Root, "certificate.pem"), filepath.Join(p.Root, "key.pem")
			want := "申请或导入证书"
			if coreFailure {
				want = "生成与校验内核配置"
				bundle := issuanceBundle(t, "node.example.com")
				if err := os.WriteFile(cp, bundle.Certificate, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(kp, bundle.PrivateKey, 0600); err != nil {
					t.Fatal(err)
				}
				p.Core = filepath.Join(p.Root, "fake-core")
				if err := os.WriteFile(p.Core, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			err := initialize(context.Background(), p, []string{"--domain", "node.example.com", "--address", "8.8.8.8", "--certificate", cp, "--key", kp, "--firewall", "manual"}, strings.NewReader(""), &out)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("wrong failure stage: %v", err)
			}
			var errOut bytes.Buffer
			menu(context.Background(), p, strings.NewReader("3\n0\n"), &out, &errOut)
			if !strings.Contains(errOut.String(), "安装未完成") || !strings.Contains(errOut.String(), want) || strings.Contains(errOut.String(), "dial unix") {
				t.Fatal("menu lost installation stage", errOut.String())
			}
		})
	}
}

func TestSubscriptionAllowsReadyAndLegacyInstallations(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		root, err := os.MkdirTemp("", "nk-sub-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(root) })
		p := makePaths(root, "")
		if err := os.MkdirAll(p.Run, 0700); err != nil {
			t.Fatal(err)
		}
		db, err := p.db()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		c, _ := model.New()
		c.Domain = "node.example.com"
		if err := db.Update(func(r *store.Record) error { r.Config = c; return nil }); err != nil {
			t.Fatal(err)
		}
		if !legacy {
			if err := saveHost(p, hostManifest{InitPhase: "ready"}); err != nil {
				t.Fatal(err)
			}
			if err := saveInstallProgress(p, "完成", true); err != nil {
				t.Fatal(err)
			}
		}
		ln, err := net.Listen("unix", filepath.Join(p.Run, "admin.sock"))
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: httpapi.Admin(editBackend{certBackend{db}})}
		go server.Serve(ln)
		t.Cleanup(func() { server.Close() })
		var out bytes.Buffer
		if err := execute(context.Background(), p, []string{"subscription"}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "/s/"+c.Token+"/config.yaml") {
			t.Fatal("subscription URL changed")
		}
		server.Close()
		err = execute(context.Background(), p, []string{"subscription"}, strings.NewReader(""), &out)
		if err == nil || strings.Contains(err.Error(), "安装未完成") {
			t.Fatalf("ready service outage misclassified: %v", err)
		}
	}
}

func TestWizardUnsupportedAutoOffersExplicitManualChoice(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	deps := wizardDeps{
		Hostname: func() (string, error) { return "host", nil },
		Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "JP", nil },
		Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
			return []cloudflare.Zone{{ID: "zone", Name: "example.com", Status: "active"}}, nil
		},
		Records: func(context.Context, string, string, string) ([]cloudflare.Record, error) { return nil, nil },
		Probe:   func(context.Context, model.Reality) error { return nil },
	}
	answers := []string{"cloudflare", "", "private-test-token", "1", "node", "owner@example.com", "", "", "", "", "", "", "", "", "1@0", "auto", "manual", "yes"}
	input, output, err := runWizardTTY(t, answers, deps)
	if err != nil || input.Firewall != "manual" || !strings.Contains(output, "不支持") {
		t.Fatalf("expected explicit manual fallback, firewall=%s error=%v output=%s", input.Firewall, err, output)
	}
}

// Without firewall tools, auto must stop before token copying, DNS, ACME,
// runtime configuration or database publication. No real host is mutated.
func TestInitUnsupportedFirewallStopsBeforeConfiguration(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	p := makePaths(t.TempDir(), "")
	var out bytes.Buffer
	err := initialize(context.Background(), p, []string{"--domain", "node.example.com", "--address", "8.8.8.8", "--firewall", "auto", "--token-file", "/missing-token"}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "防火墙预检") || !strings.Contains(err.Error(), "--firewall manual") {
		t.Fatalf("expected actionable preflight error, got %v", err)
	}
	for _, path := range []string{filepath.Join(p.Etc, "runtime.json"), filepath.Join(p.Etc, "cloudflare.token"), filepath.Join(p.Data, "state.db"), filepath.Join(p.Data, "certs")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("preflight failure left installation artifact %s: %v", path, err)
		}
	}
}

func TestInitManualSkipsFirewallAndReportsCredentialFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	p := makePaths(t.TempDir(), "")
	var out bytes.Buffer
	err := initialize(context.Background(), p, []string{"--domain", "node.example.com", "--address", "8.8.8.8", "--firewall", "manual", "--token-file", "/missing-token"}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "凭据") || !strings.Contains(err.Error(), "重新运行") {
		t.Fatalf("expected credential stage and retry instructions, got %v", err)
	}
	err = execute(context.Background(), p, []string{"subscription"}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "安装未完成") || !strings.Contains(err.Error(), "凭据") {
		t.Fatalf("lost failed installation stage: %v", err)
	}
}

func TestInitAutoPreflightIsReadOnlyAndChecksIPv6(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	// Only read-only IPv4 inspection works. Any mutating operation is rejected.
	script := "#!/bin/sh\ncase \"$*\" in '-S INPUT') exit 0;; '-C INPUT '*) exit 1;; *) exit 99;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "iptables"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		p := makePaths(t.TempDir(), "")
		args := []string{"--domain", "node.example.com", "--address", "8.8.8.8", "--firewall", "auto", "--token-file", "/missing-token"}
		if ipv6 {
			args = append(args, "--ipv6")
		}
		var out bytes.Buffer
		err := initialize(context.Background(), p, args, strings.NewReader(""), &out)
		want := "凭据"
		if ipv6 {
			want = "防火墙预检"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("ipv6=%v: expected %s, got %v", ipv6, want, err)
		}
	}
}

func TestSetupResumePreflightsBeforeWritingConfig(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("setup requires root")
	}
	t.Setenv("PATH", t.TempDir())
	p := makePaths(t.TempDir(), "")
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.Domain, c.Address = "node.example.com", "8.8.8.8"
	for _, dir := range []string{p.Etc, p.Opt} {
		if err := platform.Claim(dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeJSON(filepath.Join(p.Etc, "setup.json"), setupInput{Config: c, Firewall: "auto"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = setupCommand(context.Background(), p, []string{"--resume"}, strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "防火墙预检") || !strings.Contains(err.Error(), "manual") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.Etc, "setup-config.json")); !os.IsNotExist(err) {
		t.Fatal("config written before preflight", err)
	}
}

func TestSubscriptionExplainsIncompleteInstallWithoutSocketError(t *testing.T) {
	for _, phase := range []string{"", "prepared", "configured"} {
		t.Run(phase, func(t *testing.T) {
			p := makePaths(t.TempDir(), "")
			if phase != "" {
				if err := saveHost(p, hostManifest{InitPhase: phase}); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			err := execute(context.Background(), p, []string{"subscription"}, strings.NewReader(""), &out)
			if err == nil || !strings.Contains(err.Error(), "安装未完成") || !strings.Contains(err.Error(), "nodekit") || strings.Contains(err.Error(), "dial unix") {
				t.Fatalf("expected incomplete installation guidance, got %v", err)
			}
		})
	}
}
