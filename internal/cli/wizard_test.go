package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/terminal"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWizardCollectsCandidateWithoutSideEffects(t *testing.T) {
	root := t.TempDir()
	tokenFile := filepath.Join(root, "token")
	os.WriteFile(tokenFile, []byte("private-test-token"), 0600)
	deps := wizardDeps{
		Hostname: func() (string, error) { return "system-host", nil },
		Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "JP", nil },
		Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
			return []cloudflare.Zone{{ID: "zone", Name: "example.com", Status: "active"}}, nil
		},
		Records: func(context.Context, string, string, string) ([]cloudflare.Record, error) { return nil, nil },
		Probe:   func(context.Context, model.Reality) error { return nil },
	}
	// mode, address, token file, zone, subdomain, email, prefix, country, SNI,
	// quota, expiry, reset day/hour, firewall, explicit adoption, final confirmation.
	input := strings.Join([]string{"cloudflare", "1.1.1.1", tokenFile, "1", "node", "owner@example.com", "my-host", "US", "addons.mozilla.org", "", "", "", "", "", "1@0", "auto", "yes"}, "\n") + "\n"
	var out bytes.Buffer
	s := terminal.New(strings.NewReader(input), &out)
	setup, err := collectSetup(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err, out.String())
	}
	if setup.Config.Domain != "node.example.com" || setup.Config.Address != "1.1.1.1" || setup.Config.NodeName(setup.Config.Protocols[0]) != "🇺🇸 my-host · VLESS" || setup.Config.Quota != 0 || !setup.Config.ManagedDNS {
		t.Fatal("incorrect wizard candidate")
	}
	if strings.Contains(out.String(), "private-test-token") {
		t.Fatal("Token echoed")
	}
	if _, err = os.Stat(filepath.Join(root, "state.db")); !os.IsNotExist(err) {
		t.Fatal("input collection committed state")
	}
	_, err = collectSetup(context.Background(), terminal.New(strings.NewReader(""), &out), deps)
	if err == nil {
		t.Fatal("EOF accepted as approval")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = collectSetup(ctx, s, deps)
	if !errors.Is(err, terminal.ErrCanceled) {
		t.Fatal("cancel ignored", err)
	}
}

func TestManagedBootstrapDefaults(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	args := []string{"--root", root, "init", "--domain", "node.example.com", "--address", "8.8.8.8", "--subscription-mode", "cloudflare", "--managed-dns", "--dns-zone", "zone", "--dry-run"}
	if code := Run(context.Background(), args, strings.NewReader(""), &out, &out); code != 0 {
		t.Fatal(code, out.String())
	}
	b, err := os.ReadFile(filepath.Join(root, "etc/nodekit/bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c model.Config
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if !c.ManagedDNS || c.DisplayMode != "flag-host" || c.Name == "" || c.Reality.ServerName != "addons.mozilla.org" {
		t.Fatal("missing new installation defaults")
	}
	if _, err = os.Stat(filepath.Join(root, "root/nodekit-cloudflare.token")); !os.IsNotExist(err) {
		t.Fatal("dry run saved credentials")
	}
}

func TestSetupRefusesNonTTYPrompt(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"--root", t.TempDir(), "setup"}, strings.NewReader(""), &out, &out); code == 0 {
		t.Fatal("unattended setup accepted")
	}
	if !strings.Contains(out.String(), "终端") {
		t.Fatal("did not explain non-TTY setup", out.String())
	}
}

func TestWizardRejectsAdoptionWithoutExplicitConsent(t *testing.T) {
	root := t.TempDir()
	tokenFile := filepath.Join(root, "token")
	if err := os.WriteFile(tokenFile, []byte("private-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	deps := wizardDeps{Hostname: func() (string, error) { return "host", nil }, Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "", nil }, Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
		return []cloudflare.Zone{{ID: "z", Name: "example.com", Status: "active"}}, nil
	}, Records: func(context.Context, string, string, string) ([]cloudflare.Record, error) {
		return []cloudflare.Record{{ID: "record", Type: "A", Name: "node.example.com", Content: "1.1.1.1"}}, nil
	}, Probe: func(context.Context, model.Reality) error { t.Fatal("probe after rejected adoption"); return nil }}
	var out bytes.Buffer
	input := strings.Join([]string{"cloudflare", "", tokenFile, "1", "node", "no"}, "\n") + "\n"
	if _, err := collectSetup(context.Background(), terminal.New(strings.NewReader(input), &out), deps); !errors.Is(err, terminal.ErrCanceled) {
		t.Fatal("adoption consent ignored", err)
	}
	if !strings.Contains(out.String(), "彻底卸载会删除此记录") {
		t.Fatal("adoption lacks deletion semantics")
	}
}
