package integration

import (
	"bytes"
	"context"
	"fmt"
	"nodekit/internal/cli"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"os/exec"
	"testing"
)

func exerciseHostSafety(t *testing.T, invoke func(...string), cfg *model.Config) {
	t.Helper()
	oldPort := cfg.Protocols[0].Port
	port := freePort(t)
	invoke("protocol", "port", "vless", fmt.Sprint(port))
	cfg.Protocols[0].Port = port
	rule := func(p int) []string {
		return []string{"-C", "INPUT", "-p", "tcp", "--dport", fmt.Sprint(p), "-m", "comment", "--comment", fmt.Sprintf("nodekit:tcp:%d", p), "-j", "ACCEPT"}
	}
	if exec.Command("iptables", rule(port)...).Run() != nil {
		t.Fatal("new protocol port was not allowed")
	}
	if exec.Command("iptables", rule(oldPort)...).Run() == nil {
		t.Fatal("old protocol firewall rule remains")
	}
	lock, e := platform.AcquireLock("/opt/nodekit/operation.lock")
	if e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	code := cli.Run(context.Background(), []string{"protocol", "port", "vless", fmt.Sprint(freePort(t))}, bytes.NewReader(nil), &output, &output)
	lock.Close()
	if code == 0 {
		t.Fatal("concurrent privileged operation was accepted")
	}
	if exec.Command("iptables", rule(port)...).Run() != nil {
		t.Fatal("losing operation removed committed firewall rule")
	}
	path := "/etc/systemd/system/nodekit-core.service"
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	defer os.WriteFile(path, original, 0644)
	if e = os.WriteFile(path, []byte("[Unit]\nDescription=Foreign replacement\n"), 0644); e != nil {
		t.Fatal(e)
	}
	output.Reset()
	if code = cli.Run(context.Background(), []string{"uninstall"}, bytes.NewReader(nil), &output, &output); code == 0 {
		t.Fatal("uninstaller took over foreign unit")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "nodekit-manager.service").Run() != nil {
		t.Fatal("foreign-unit refusal stopped active service")
	}
	if e = os.WriteFile(path, original, 0644); e != nil {
		t.Fatal(e)
	}
}
