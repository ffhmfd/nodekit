package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestUFWInsertionDoesNotReplaceForeignPacketIdentity(t *testing.T) {
	for _, tc := range []struct{ name, action, command, suffix string }{
		{"deny", "DENY IN", "deny", ""},
		{"reject", "REJECT IN", "reject", ""},
		{"limit", "LIMIT IN", "limit", ""},
		{"logged allow", "ALLOW IN", "allow log", " (log)"},
	} {
		for _, family := range []string{"ipv4", "ipv6"} {
			t.Run(tc.name+"/"+family, func(t *testing.T) {
				s := &familyFirewall{ufw: true, rules: map[string]bool{}}
				replaced := false
				run := func(ctx context.Context, args ...string) ([]byte, error) {
					cmd := strings.Join(args, " ")
					if strings.HasPrefix(cmd, "ufw allow ") {
						replaced = true
					}
					out, err := s.run(ctx, args...)
					if !replaced && cmd == "ufw status" {
						v6 := ""
						if family == "ipv6" {
							v6 = " (v6)"
						}
						out = append(out, []byte(fmt.Sprintf("24441/tcp%s %s Anywhere%s%s # foreign owner\n", v6, tc.action, v6, tc.suffix))...)
					}
					if !replaced && cmd == "ufw show added" {
						out = append(out, []byte("ufw "+tc.command+" 24441/tcp comment 'foreign owner'\n")...)
					}
					return out, err
				}
				f := Firewall{Run: run}
				err := f.Apply(context.Background(), []Binding{{Network: "tcp", Port: 24441, Family: family}})
				if replaced || err == nil {
					t.Fatalf("foreign packet rule was replaced: replaced=%v err=%v", replaced, err)
				}
				if len(s.rules) != 0 {
					t.Fatal("project rule created over foreign action", s.rules)
				}
			})
		}
	}
}

func TestUFWRestoreDoesNotAddMissingGenericFamily(t *testing.T) {
	for _, intentDual := range []bool{false, true} {
		t.Run(fmt.Sprint(intentDual), func(t *testing.T) {
			s := &familyFirewall{ufw: true, skip6: true, rules: map[string]bool{"tcp 24441 any nodekit:tcp:24441": true}}
			f := Firewall{Run: s.run}
			old, err := f.Snapshot(context.Background(), []Binding{{Network: "tcp", Port: 24441, IPv6: intentDual}})
			if err != nil {
				t.Fatal(err)
			}
			next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv4"}}
			if err = f.Reconcile(context.Background(), old, next); err != nil {
				t.Fatal(err)
			}
			// The IPv6 backend becomes available after the old v4-only generic
			// rule was removed. Replaying `to any` would now broaden coverage.
			s.skip6 = false
			if err = f.Restore(context.Background(), append(old, next...), old); err != nil {
				t.Fatal(err)
			}
			status, _ := s.run(context.Background(), "ufw", "status")
			if strings.Contains(string(status), "(v6)") || !strings.Contains(string(status), "24441/tcp ALLOW") {
				t.Fatal("compensation changed old physical families", string(status))
			}
		})
	}
}

// Frozen public v0.2.1 UFW Remove behavior, transcribed from
// dist/github-nodekit/internal/platform/firewall.go (read-only reference).
// It decodes only the three old JSON fields and deletes by the OLD exact tag.
func frozenLegacyUFWRemove(ctx context.Context, run Runner, raw []byte) error {
	var bindings []struct {
		Network string `json:"network"`
		Port    int    `json:"port"`
		IPv6    bool   `json:"ipv6"`
	}
	if err := json.Unmarshal(raw, &bindings); err != nil {
		return err
	}
	for _, b := range bindings {
		tag := fmt.Sprintf("nodekit:%s:%d", b.Network, b.Port)
		status, err := run(ctx, "ufw", "status")
		if err != nil {
			return err
		}
		owned := false
		for _, line := range strings.Split(string(status), "\n") {
			parts := strings.SplitN(line, "#", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) == tag {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		if _, err = run(ctx, "ufw", "--force", "delete", "allow", "proto", b.Network, "from", "any", "to", "any", "port", fmt.Sprint(b.Port), "comment", tag); err != nil {
			return err
		}
	}
	return nil
}

func TestUFWLegacyOnlyInstallRemainsCleanableByFrozenOldHelper(t *testing.T) {
	s := &familyFirewall{ufw: true, shortAdded: true, rules: map[string]bool{}}
	// UFW's generic delete expands into matching v4 and v6 packet identities.
	// Its reconstructed short command does not retain the original `to` token.
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 3 && args[0] == "ufw" && args[1] == "--force" && args[2] == "delete" {
			value := func(k string) string {
				for i := 0; i < len(args)-1; i++ {
					if args[i] == k {
						return args[i+1]
					}
				}
				return ""
			}
			if value("to") == "any" {
				for rule := range s.rules {
					p := strings.Fields(rule)
					if p[0] == value("proto") && p[1] == value("port") && p[3] == value("comment") {
						delete(s.rules, rule)
					}
				}
				return nil, nil
			}
		}
		return s.run(ctx, args...)
	}
	bindings := []Binding{{Network: "tcp", Port: 24441}, {Network: "udp", Port: 24442}}
	f := Firewall{Run: run}
	if err := f.Apply(context.Background(), bindings); err != nil {
		t.Fatal(err)
	}
	status, _ := run(context.Background(), "ufw", "status")
	if strings.Contains(string(status), "(v6)") {
		t.Fatal("new IPv4-only install gained IPv6", string(status))
	}
	snapshot, err := f.Snapshot(context.Background(), bindings)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if err := frozenLegacyUFWRemove(context.Background(), run, raw); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 0 {
		t.Fatal("old helper silently left project allowances", s.rules)
	}
}

func TestUFWLegacyDualShortCommandsRemainIdempotent(t *testing.T) {
	s := &familyFirewall{ufw: true, shortAdded: true, rules: map[string]bool{}}
	f := Firewall{Run: s.run}
	b := []Binding{{Network: "tcp", Port: 24441, IPv6: true}}
	if err := f.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if err := f.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	status, _ := s.run(context.Background(), "ufw", "status")
	if !strings.Contains(string(status), "24441/tcp ALLOW") || !strings.Contains(string(status), "24441/tcp (v6) ALLOW") {
		t.Fatal(string(status))
	}
	if err := f.Remove(context.Background(), b); err != nil || len(s.rules) != 0 {
		t.Fatal(err, s.rules)
	}
}

func TestUFWPartialGenericDeletionCannotReportSuccess(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{"tcp 24441 any nodekit:tcp:24441": true}}
	f := Firewall{Run: func(ctx context.Context, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "--force delete") {
			delete(s.rules, "tcp 24441 any nodekit:tcp:24441")
			s.rules["tcp 24441 ::/0 nodekit:tcp:24441"] = true
			return nil, nil
		}
		return s.run(ctx, args...)
	}}
	if err := f.Remove(context.Background(), []Binding{{Network: "tcp", Port: 24441}}); err == nil {
		t.Fatal("partial physical deletion reported success", s.rules)
	}
}

func TestUFWJournaledLegacyIntentRepairsPreFixFamilyComments(t *testing.T) {
	s := &familyFirewall{ufw: true, shortAdded: true, rules: map[string]bool{"tcp 24441 0.0.0.0/0 nodekit:ipv4:tcp:24441": true}}
	f := Firewall{Run: s.run}
	next := []Binding{{Network: "tcp", Port: 24441}}
	if err := f.Apply(context.Background(), next); err == nil || !s.rules["tcp 24441 0.0.0.0/0 nodekit:ipv4:tcp:24441"] {
		t.Fatal("ensure-only startup performed format migration", err, s.rules)
	}
	old, err := f.Snapshot(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Reconcile(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:tcp:24441"] {
		t.Fatal("legacy-only reconciliation left incompatible physical identity", s.rules)
	}
}

func TestUFWSnapshotRefusesUnobservedLegacyCoverage(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{}}
	f := Firewall{Run: s.run}
	if _, err := f.Snapshot(context.Background(), []Binding{{Network: "tcp", Port: 24441}}); err == nil {
		t.Fatal("unobserved legacy intent was reported as restoration provenance")
	}
	if len(s.rules) != 0 {
		t.Fatal("snapshot mutated firewall", s.rules)
	}
}

func TestUFWRestorePreservesOnlyIPv6OldHalf(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{"tcp 24441 ::/0 nodekit:tcp:24441": true}}
	f := Firewall{Run: s.run}
	old, err := f.Snapshot(context.Background(), []Binding{{Network: "tcp", Port: 24441}})
	if err != nil {
		t.Fatal(err)
	}
	next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv4"}}
	if err = f.Reconcile(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if err = f.Restore(context.Background(), append(old, next...), old); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 ::/0 nodekit:tcp:24441"] {
		t.Fatal("compensation changed old v6-only physical coverage", s.rules)
	}
}

func TestUFWGenericWithFamilyCommentIsNotAnOwnedQualifiedRule(t *testing.T) {
	s := &familyFirewall{ufw: true, shortAdded: true, rules: map[string]bool{"tcp 24441 any nodekit:ipv4:tcp:24441": true}}
	f := Firewall{Run: s.run}
	if err := f.Apply(context.Background(), []Binding{{Network: "tcp", Port: 24441, Family: "ipv4"}}); err == nil {
		t.Fatal("generic dual-family identity accepted as exact owned IPv4 rule")
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 any nodekit:ipv4:tcp:24441"] {
		t.Fatal("mismatched identity was changed", s.rules)
	}
}

func TestUFWEnsureLegacyGenericSurvivesInsertionFailure(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			const generic = "tcp 24441 any nodekit:tcp:24441"
			s := &familyFirewall{ufw: true, fail: "ufw allow", rules: map[string]bool{generic: true}}
			bindings := []Binding{{Network: "tcp", Port: 24441}}
			if missing {
				bindings = append(bindings, Binding{Network: "tcp", Port: 24442})
			}
			// This is the no-journal startup path. Under the regression, Apply
			// deletes the existing generic, then the injected insertion fails.
			err := (Firewall{Run: s.run}).Apply(context.Background(), bindings)
			if !s.rules[generic] {
				t.Fatal("ensure-only Apply lost the still-required generic allowance", s.rules, err)
			}
			if missing && err == nil || !missing && err != nil {
				t.Fatal("unexpected ensure result", err)
			}
			for _, cmd := range s.commands {
				if strings.Contains(cmd, "--force delete") {
					t.Fatal("ensure-only Apply performed an unjournaled deletion", cmd)
				}
			}
		})
	}
}

func TestUFWEnsureExplicitFamilyRequiresJournaledGenericMigration(t *testing.T) {
	const generic = "tcp 24441 any nodekit:tcp:24441"
	s := &familyFirewall{ufw: true, rules: map[string]bool{generic: true}}
	f := Firewall{Run: s.run}
	next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv4", Address: "127.0.0.1"}}
	if err := f.Apply(context.Background(), next); err == nil {
		t.Fatal("explicit IPv4 intent silently accepted a broad legacy generic")
	}
	if len(s.rules) != 1 || !s.rules[generic] {
		t.Fatal("unprepared explicit startup mutated legacy ownership", s.rules)
	}
	old, err := f.Snapshot(context.Background(), []Binding{{Network: "tcp", Port: 24441}})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Reconcile(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:ipv4:tcp:24441"] {
		t.Fatal("journaled transition did not isolate IPv4", s.rules)
	}
}

func TestUFWJournaledLegacyMigrationStillRemovesUndesiredIPv6(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{"tcp 24441 any nodekit:tcp:24441": true}}
	f := Firewall{Run: s.run}
	old, err := f.Snapshot(context.Background(), []Binding{{Network: "tcp", Port: 24441}})
	if err != nil {
		t.Fatal(err)
	}
	next := []Binding{{Network: "tcp", Port: 24441}}
	if err = f.Reconcile(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:tcp:24441"] {
		t.Fatal("journaled family migration was weakened", s.rules)
	}
	if err = f.Restore(context.Background(), append(old, next...), old); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 any nodekit:tcp:24441"] {
		t.Fatal("journaled migration cannot restore old dual coverage", s.rules)
	}
}

func TestIPTablesEnsureDoesNotDeleteCompatibleOwnedDuplicate(t *testing.T) {
	const legacy = "iptables -p tcp --dport 24441 -m comment --comment nodekit:tcp:24441 -j ACCEPT"
	const explicit = "iptables -p tcp --dport 24441 -m comment --comment nodekit:ipv4:tcp:24441 -j ACCEPT"
	s := &familyFirewall{rules: map[string]bool{legacy: true, explicit: true}}
	if err := (Firewall{Run: s.run}).Apply(context.Background(), []Binding{{Network: "tcp", Port: 24441}}); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 2 || !s.rules[legacy] || !s.rules[explicit] {
		t.Fatal("ensure-only iptables Apply deleted an old physical identity", s.rules)
	}
}
