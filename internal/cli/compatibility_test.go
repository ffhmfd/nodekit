package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"nodekit/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilitiesIsReadonly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--root", root, "capabilities"}, bytes.NewReader(nil), &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var result struct {
		Modes []string `json:"subscription_modes"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Modes) != 2 || result.Modes[0] != "direct" || result.Modes[1] != "cloudflare" {
		t.Fatal("missing capability")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("read-only probe created state")
	}
}

func TestReleaseCompatibility(t *testing.T) {
	c, _ := model.New()
	c.Address = "8.8.8.8"
	c.SubscriptionMode = "cloudflare"
	c.SubscriptionPort = 8443
	for _, tc := range []struct {
		name, script string
		ok           bool
	}{
		{"old", "exit 2", false}, {"empty", "exit 0", false}, {"malformed", "echo garbage", false},
		{"direct-only", `echo '{"subscription_modes":["direct"]}'`, false},
		{"supported", `echo '{"subscription_modes":["direct","cloudflare"]}'`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := checkReleaseCompatibility(context.Background(), c, path); (err == nil) != tc.ok {
				t.Fatal(err)
			}
			legacy := c.Clone()
			legacy.SubscriptionMode = ""
			if err := checkReleaseCompatibility(context.Background(), legacy, "/does/not/exist"); err != nil {
				t.Fatal("legacy upgrade unexpectedly probed", err)
			}
		})
	}
}

func TestReleaseCompatibilityRequiresStateFeatures(t *testing.T) {
	for _, feature := range []string{"names", "managed-dns"} {
		t.Run(feature, func(t *testing.T) {
			c, _ := model.New()
			if feature == "names" {
				c.SetDisplayDefaults("host", "JP")
			} else {
				c.ManagedDNS = true
			}
			path := filepath.Join(t.TempDir(), "candidate")
			os.WriteFile(path, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\",\"cloudflare\"]}'\n"), 0700)
			if err := checkReleaseCompatibility(context.Background(), c, path); err == nil {
				t.Fatal("candidate ignored new state fields")
			}
			os.WriteFile(path, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\",\"cloudflare\"],\"features\":[\"node-names-v1\",\"managed-dns-v1\",\"purge-v1\"]}'\n"), 0700)
			if err := checkReleaseCompatibility(context.Background(), c, path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceHelperChoosesCompatibleCurrentRelease(t *testing.T) {
	p := makePaths(t.TempDir(), "")
	c, _ := model.New()
	c.SetDisplayDefaults("host", "JP")
	for _, name := range []string{"current", "previous"} {
		os.MkdirAll(filepath.Join(p.Opt, name), 0700)
		os.WriteFile(filepath.Join(p.Opt, name, "nodekit"), []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\"]}'\n"), 0700)
	}
	current := filepath.Join(p.Opt, "current/nodekit")
	os.WriteFile(current, []byte("#!/bin/sh\necho '{\"subscription_modes\":[\"direct\"],\"features\":[\"node-names-v1\"]}'\n"), 0700)
	got, err := serviceBinary(context.Background(), p, c)
	if err != nil || got != current {
		t.Fatal("selected incompatible recovery helper", got, err)
	}
	os.Remove(current)
	if _, err = serviceBinary(context.Background(), p, c); err == nil {
		t.Fatal("used legacy helper for new display state")
	}
}
