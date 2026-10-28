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
