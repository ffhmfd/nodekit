package cli

import (
	"context"
	"errors"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryPreflightRejectsUnusableRetainedRule(t *testing.T) {
	for _, restore := range []bool{false, true} {
		p, old, next, s := transactionFixture(t)
		f := recoveryPreflightFixture(s)
		if _, _, err := beginFirewallChangeWith(context.Background(), p, old, next, f); err != nil {
			t.Fatal(err)
		}
		m, err := loadHost(p)
		if err != nil {
			t.Fatal(err)
		}
		if !restore {
			next.Revision++
		}
		base := f.Run
		f.Run = func(ctx context.Context, args ...string) ([]byte, error) {
			out, err := base(ctx, args...)
			if strings.Join(args, " ") == "ufw status" {
				var lines []string
				for _, line := range strings.Split(string(out), "\n") {
					if !strings.Contains(line, "nodekit:ipv4:tcp:24441") {
						lines = append(lines, line)
					}
				}
				out = []byte(strings.Join(lines, "\n"))
			}
			return out, err
		}
		s.beforeMutation = func() { t.Fatal("preflight mutated retained rule") }
		if err := checkRecoveryFirewall(context.Background(), next, "auto", m, f); err == nil {
			t.Fatalf("restore=%v: accepted stored desired rule without live allowance", restore)
		}
	}
}

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

func TestRecoveryPreflightAllowsJournalOwnedMigration(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	f := recoveryPreflightFixture(s)
	if _, _, err := beginFirewallChangeWith(context.Background(), p, old, next, f); err != nil {
		t.Fatal(err)
	}
	m, err := loadHost(p)
	if err != nil {
		t.Fatal(err)
	}
	// Same preflight entry used by resume, with the database still on old.
	s.beforeMutation = func() { t.Fatal("recovery preflight mutated firewall") }
	if err := checkRecoveryFirewall(context.Background(), old, "auto", m, f); err != nil {
		t.Fatal("journal-owned staging blocked recovery", err)
	}
	s.beforeMutation = nil
	m, err = reconcileFirewallWith(context.Background(), p, m, old, f)
	if err != nil || m.PendingFirewall != nil || !s.rules["any 24441 nodekit:tcp:24441"] {
		t.Fatal("failed to restore journaled rules", err, s.rules)
	}
}

func TestRecoveryPreflightStillRejectsForeignUFWRule(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	f := recoveryPreflightFixture(s)
	if _, _, err := beginFirewallChangeWith(context.Background(), p, old, next, f); err != nil {
		t.Fatal(err)
	}
	delete(s.rules, "0.0.0.0/0 24441 nodekit:ipv4:tcp:24441")
	s.rules["0.0.0.0/0 24441 foreign-owner"] = true
	m, err := loadHost(p)
	if err != nil {
		t.Fatal(err)
	}
	s.beforeMutation = func() { t.Fatal("recovery preflight mutated firewall") }
	if err := checkRecoveryFirewall(context.Background(), old, "auto", m, f); err == nil {
		t.Fatal("foreign UFW rule accepted as journal-owned")
	}
	if !s.rules["0.0.0.0/0 24441 foreign-owner"] {
		t.Fatal("preflight mutated foreign rule")
	}
}

func recoveryPreflightFixture(s *journalFirewall) platform.Firewall {
	return platform.Firewall{Run: func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 2 && args[0] == "ufw" && args[1] == "--dry-run" {
			return []byte("*filter\nCOMMIT\n"), nil
		}
		return s.run(ctx, args...)
	}}
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
