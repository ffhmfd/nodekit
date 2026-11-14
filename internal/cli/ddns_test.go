package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDDNSBootstrapPreservesHostname(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	args := []string{"--root", root, "init", "--domain", "node.example.com", "--address", "DDNS.EXAMPLE.COM.", "--subscription-mode", "cloudflare", "--managed-dns", "--dry-run"}
	if code := Run(context.Background(), args, strings.NewReader(""), &out, &out); code != 0 {
		t.Fatal(out.String())
	}
	b, err := os.ReadFile(filepath.Join(root, "etc/nodekit/bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c model.Config
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.Address != "ddns.example.com" || !c.ManagedDNS {
		t.Fatal("DDNS was not persisted", c.Address)
	}
}

func TestDDNSWizardAcceptsHostnameAndExistingCNAME(t *testing.T) {
	deps := wizardDeps{
		Hostname: func() (string, error) { return "host", nil },
		Discover: func(context.Context) (string, string, error) { return "8.8.8.8", "JP", nil },
		Zones: func(context.Context, string) ([]cloudflare.Zone, error) {
			return []cloudflare.Zone{{ID: "z", Name: "example.com", Status: "active"}}, nil
		},
		Records: func(context.Context, string, string, string) ([]cloudflare.Record, error) {
			return []cloudflare.Record{{ID: "r", Type: "CNAME", Name: "node.example.com", Content: "old.example.com"}}, nil
		},
		Probe: func(context.Context, model.Reality) error { return nil },
	}
	answers := []string{"cloudflare", "DDNS.EXAMPLE.COM.", "private-test-token", "1", "node", "adopt", "owner@example.com", "host", "JP", "", "", "", "", "", "", "1@0", "manual", "yes"}
	setup, output, err := runWizardTTY(t, answers, deps)
	if err != nil {
		t.Fatal(err, output)
	}
	if setup.Config.Address != "ddns.example.com" || setup.Config.IPv6 || setup.Previous == nil || setup.Previous.Type != "CNAME" {
		t.Fatal("wrong DDNS wizard result")
	}
}

func TestDDNSTransactionAndLegacyDiscovery(t *testing.T) {
	old, _ := model.New()
	old.Address = "8.8.8.8"
	next := old.Clone()
	next.Address, next.ManagedDNS = "ddns.example.com", true
	next.SubscriptionMode, next.SubscriptionPort = "cloudflare", 8443
	previous := cloudflare.Record{ID: "record", Type: "A", Name: next.Domain, Content: "8.8.8.8", TTL: 1, Proxied: true}
	api := &memoryDNS{record: &previous}
	m := hostManifest{InstallationID: "instance"}
	save := func() error { return nil }
	if err := prepareDNSChange(context.Background(), api, &m, old, next, "zone", &previous, save); err != nil {
		t.Fatal(err)
	}
	if api.record.Type != "CNAME" || api.record.Content != "ddns.example.com" || !api.record.Proxied {
		t.Fatal("wrong subscription origin", api.record)
	}
	if !slices.Contains(hostFeatures(m), "ddns-cname-v1") {
		t.Fatal("pending CNAME can be processed by old binary")
	}
	if err := completeDNSChange(context.Background(), api, &m, save); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(hostFeatures(m), "ddns-cname-v1") {
		t.Fatal("CNAME ownership lost compatibility requirement")
	}
	if _, err := discoverLegacyDNS(context.Background(), api, "zone", next); err != nil {
		t.Fatal(err)
	}
	api.record.Content = "somebody-else.example.com"
	if _, err := discoverLegacyDNS(context.Background(), api, "zone", next); err == nil {
		t.Fatal("foreign CNAME adopted for purge")
	}
}

func TestDDNSReleaseCompatibilityAndRetention(t *testing.T) {
	c, _ := model.New()
	c.Address = "ddns.example.com"
	bin := filepath.Join(t.TempDir(), "candidate")
	for _, capable := range []bool{false, true} {
		features := ""
		if capable {
			features = `,"features":["ddns-cname-v1"]`
		}
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\",\"cloudflare\"]"+features+"}'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := checkReleaseCompatibility(context.Background(), c, bin); (err == nil) != capable {
			t.Fatalf("capable=%t: %v", capable, err)
		}
	}
	p := makePaths(t.TempDir(), "")
	m := hostManifest{}
	if err := saveRetainedRequirements(p, &m, c); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.RequiredFeatures, "ddns-cname-v1") {
		t.Fatal("retained DDNS configuration can downgrade")
	}
}
