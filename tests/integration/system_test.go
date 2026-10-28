package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"nodekit/internal/cli"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in test refuses any existing installation and cleans only resources it created.
func TestSystemLifecycle(t *testing.T) {
	if os.Getenv("NODEKIT_SYSTEM_TEST") != "1" {
		t.Skip("requires explicit root/systemd lifecycle opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	archive := os.Getenv("NODEKIT_RELEASE_ARCHIVE")
	if archive == "" {
		t.Fatal("release required")
	}
	paths := []string{"/opt/nodekit", "/etc/nodekit", "/var/lib/nodekit", "/run/nodekit", "/usr/local/bin/nodekit", "/etc/tmpfiles.d/nodekit.conf", "/etc/systemd/system/nodekit-core.service", "/etc/systemd/system/nodekit-manager.service"}
	for _, p := range paths {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatalf("refusing existing resource %s", p)
		}
	}
	if exec.Command("id", "nodekit").Run() == nil || exec.Command("getent", "group", "nodekit").Run() == nil {
		t.Fatal("refusing existing nodekit user/group")
	}
	for _, name := range []string{"nodekit-core.service", "nodekit-manager.service"} {
		state, err := exec.Command("systemctl", "show", "--property=LoadState", "--value", name).Output()
		if err != nil || string(bytes.TrimSpace(state)) != "not-found" {
			t.Fatal("refusing pre-existing loaded unit", name)
		}
	}
	cfg, _ := model.New()
	cfg.Name = "NodeKit-system-test"
	for i := range cfg.Protocols {
		cfg.Protocols[i].Port = freePort(t)
	}
	cfg.SubscriptionPort = freePort(t)
	if os.Getenv("NODEKIT_SYSTEM_MODE") == "cloudflare" {
		cfg.SubscriptionMode = "cloudflare"
		cfg.SubscriptionPort = availableCloudflarePort(t, 0)
		cfg.Address = "8.8.8.8"
	}
	defer func() {
		_ = exec.Command("systemctl", "disable", "--now", "nodekit-manager.service", "nodekit-core.service").Run()
		_ = (platform.Firewall{}).Remove(context.Background(), platform.Bindings(cfg))
		for _, p := range paths {
			_ = os.RemoveAll(p)
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "reset-failed", "nodekit-manager.service", "nodekit-core.service").Run()
		_ = exec.Command("userdel", "nodekit").Run()
		_ = exec.Command("groupdel", "nodekit").Run()
	}()
	invoke := func(args ...string) {
		t.Helper()
		var output bytes.Buffer
		if code := cli.Run(context.Background(), args, bytes.NewReader(nil), &output, &output); code != 0 {
			log, _ := exec.Command("journalctl", "-u", "nodekit-core", "-u", "nodekit-manager", "-n", "30", "--no-pager").CombinedOutput()
			t.Fatalf("command %s failed: %s\n%s", args[0], output.String(), log)
		}
	}
	f, e := os.Open(archive)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		t.Fatal(e)
	}
	f.Close()
	sha := fmt.Sprintf("%x", h.Sum(nil))
	if script := os.Getenv("NODEKIT_INSTALL_SCRIPT"); script != "" {
		if output, e := exec.Command("bash", script, "--file", archive, "--sha256", sha).CombinedOutput(); e != nil {
			t.Fatalf("installer entrypoint failed: %v %s", e, output)
		}
	} else {
		invoke("install", "--file", archive, "--sha256", sha)
	}
	dir := t.TempDir()
	cp, kp, _ := testCert(t, dir)
	configPath := filepath.Join(dir, "config.json")
	b, _ := json.Marshal(cfg)
	if e = os.WriteFile(configPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	exerciseTransientCollision(t, configPath, cp, kp)
	invoke("init", "--config", configPath, "--certificate", cp, "--key", kp, "--firewall", "auto")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if exec.Command("systemctl", "is-active", "--quiet", "nodekit-manager.service").Run() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manager never became active")
		}
		time.Sleep(100 * time.Millisecond)
	}
	invoke("status")
	if cfg.EffectiveSubscriptionMode() == "cloudflare" {
		exerciseLegacyRejection(t)
	}
	invoke("config", "set", "quota", "2GB")
	invoke("usage", "reset")
	exerciseHostSafety(t, invoke, &cfg)
	exerciseRootRecovery(t, invoke, false)
	exerciseRootRecovery(t, invoke, true)
	exerciseFailedUpgrade(t, invoke)
	invoke("upgrade", "--file", archive, "--sha256", sha)
	invoke("rollback")
	invoke("uninstall")
	if _, e = os.Stat("/var/lib/nodekit/state.db"); e != nil {
		t.Fatal("uninstall lost preserved state")
	}
	invoke("install", "--file", archive, "--sha256", sha)
	invoke("resume")
	invoke("uninstall", "--purge")
	for _, p := range paths {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Errorf("resource remains: %s", p)
		}
	}
}
