package integration

import (
	"bytes"
	"context"
	"nodekit/internal/cli"
	"os/exec"
	"testing"
)

func exerciseTransientCollision(t *testing.T, config, certificate, key string) {
	t.Helper()
	if b, e := exec.Command("systemd-run", "--unit=nodekit-core.service", "--collect", "--property=RuntimeMaxSec=60", "/bin/sleep", "60").CombinedOutput(); e != nil {
		t.Fatal("test transient unit creation failed", e, string(b))
	}
	defer exec.Command("systemctl", "stop", "nodekit-core.service").Run()
	var output bytes.Buffer
	code := cli.Run(context.Background(), []string{"init", "--config", config, "--certificate", certificate, "--key", key, "--firewall", "auto"}, bytes.NewReader(nil), &output, &output)
	if code == 0 {
		t.Fatal("adopted foreign transient unit")
	}
	if exec.Command("id", "nodekit").Run() == nil {
		t.Fatal("preflight conflict created service account")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "nodekit-core.service").Run() != nil {
		t.Fatal("preflight disturbed conflicting unit")
	}
	if e := exec.Command("systemctl", "stop", "nodekit-core.service").Run(); e != nil {
		t.Fatal(e)
	}
	_ = exec.Command("systemctl", "reset-failed", "nodekit-core.service").Run()
}
