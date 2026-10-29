package cli

import (
	"context"
	"errors"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"path/filepath"
	"testing"
)

func TestFirewallParentStartReconcilesInterruptedTargetBeforeLockedHook(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	if err := writeJSON(filepath.Join(p.Etc, "runtime.json"), runtimeConfig{Firewall: "auto"}); err != nil {
		t.Fatal(err)
	}
	f := platform.Firewall{Run: s.run}
	if _, _, err := beginFirewallChangeWith(context.Background(), p, old, next, f); err != nil {
		t.Fatal(err)
	}
	inspected := false
	m, err := prepareFirewallStartWith(context.Background(), p, f, func(context.Context, paths) (model.Config, error) { inspected = true; return old, nil })
	if err != nil || !inspected || m.PendingFirewall != nil {
		t.Fatal("parent did not settle authoritative old revision", err)
	}
	if !s.rules["any 24441 nodekit:tcp:24441"] || !s.rules["any 24446 nodekit:tcp:24446"] || len(s.rules) != 2 {
		t.Fatal("stale staged target survived parent recovery", s.rules)
	}
	if err := f.Apply(context.Background(), firewallApplyBindings(m)); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 2 || !s.rules["any 24441 nodekit:tcp:24441"] {
		t.Fatal("locked hook replayed stale target")
	}
}

func TestFirewallParentStartPreservesJournalWhenInspectionUnavailable(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	if err := writeJSON(filepath.Join(p.Etc, "runtime.json"), runtimeConfig{Firewall: "auto"}); err != nil {
		t.Fatal(err)
	}
	f := platform.Firewall{Run: s.run}
	if _, _, err := beginFirewallChangeWith(context.Background(), p, old, next, f); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareFirewallStartWith(context.Background(), p, f, func(context.Context, paths) (model.Config, error) {
		return model.Config{}, errors.New("service inspection unavailable")
	}); err == nil {
		t.Fatal("unknown authoritative config accepted")
	}
	m, _ := loadHost(p)
	if m.PendingFirewall == nil {
		t.Fatal("failed start discarded journal")
	}
}
