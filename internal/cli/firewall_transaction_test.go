package cli

import (
	"context"
	"errors"
	"fmt"
	"nodekit/internal/cloudflare"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type journalFirewall struct {
	rules          map[string]bool
	fail           string
	beforeMutation func()
}

func (s *journalFirewall) run(_ context.Context, args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	if s.fail != "" && strings.Contains(cmd, s.fail) {
		return nil, errors.New("injected firewall failure")
	}
	if cmd == "ufw status" {
		out := "Status: active\n"
		for key := range s.rules {
			p := strings.Fields(key)
			if p[0] != "::/0" {
				out += fmt.Sprintf("%s/tcp ALLOW Anywhere # %s\n", p[1], p[2])
			}
			if p[0] != "0.0.0.0/0" {
				out += fmt.Sprintf("%s/tcp (v6) ALLOW Anywhere (v6) # %s\n", p[1], p[2])
			}
		}
		return []byte(out), nil
	}
	if cmd == "ufw show added" {
		var out string
		for key := range s.rules {
			p := strings.Fields(key)
			out += fmt.Sprintf("ufw allow proto tcp from any to %s port %s comment '%s'\n", p[0], p[1], p[2])
		}
		return []byte(out), nil
	}
	if s.beforeMutation != nil {
		s.beforeMutation()
	}
	value := func(k string) string {
		for i := 0; i < len(args)-1; i++ {
			if args[i] == k {
				return args[i+1]
			}
		}
		return ""
	}
	if value("proto") != "tcp" {
		return nil, fmt.Errorf("unexpected %s", cmd)
	}
	key := strings.Join([]string{value("to"), value("port"), value("comment")}, " ")
	if args[1] == "--force" {
		delete(s.rules, key)
	} else {
		s.rules[key] = true
	}
	return nil, nil
}
func transactionFixture(t *testing.T) (paths, model.Config, model.Config, *journalFirewall) {
	t.Helper()
	p := makePaths(t.TempDir(), "")
	if err := os.MkdirAll(p.Etc, 0700); err != nil {
		t.Fatal(err)
	}
	old, _ := model.New()
	for i := range old.Protocols {
		old.Protocols[i].Enabled = old.Protocols[i].Type == "vless"
	}
	next := old.Clone()
	next.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2606:4700::1111", Protocols: []string{"vless"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	m := hostManifest{Firewall: []platform.Binding{{Network: "tcp", Port: 24446}, {Network: "tcp", Port: 24441}}}
	if err := saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	s := &journalFirewall{rules: map[string]bool{"any 24441 nodekit:tcp:24441": true, "any 24446 nodekit:tcp:24446": true}}
	return p, old, next, s
}

func TestFirewallJournalUsesManifestAndRestoresPhysicalGeneric(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	s.beforeMutation = func() {
		m, err := loadHost(p)
		if err != nil || m.PendingFirewall == nil {
			t.Fatal("firewall mutated before durable journal", m, err)
		}
		foundFalse, foundTrue := false, false
		for _, b := range m.PendingFirewall.Old {
			if b.Port == 24441 && b.Family == "" {
				if b.IPv6 {
					foundTrue = true
				} else {
					foundFalse = true
				}
			}
		}
		if !foundFalse || !foundTrue {
			t.Fatal("raw legacy/physical provenance lost", m.PendingFirewall.Old)
		}
	}
	_, abort, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
	if err != nil {
		t.Fatal(err)
	}
	if s.rules["any 24441 nodekit:tcp:24441"] {
		t.Fatal("generic not migrated", s.rules)
	}
	if err = abort(); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 2 || !s.rules["any 24441 nodekit:tcp:24441"] {
		t.Fatal("physical old ownership not restored", s.rules)
	}
	m, err := loadHost(p)
	if err != nil || m.PendingFirewall != nil {
		t.Fatal(m, err)
	}
}

func TestFirewallJournalFailedApplyAndAbortRetainsRecoveryAndRetry(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	// Addition and compensation both fail after the old generic has gone.
	s.fail = "ufw allow"
	_, _, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
	if err == nil {
		t.Fatal("apply failure swallowed")
	}
	m, _ := loadHost(p)
	if m.PendingFirewall == nil {
		t.Fatal("uncertain compensation cleared journal")
	}
	s.fail = ""
	if _, err = reconcileFirewallWith(context.Background(), p, m, old, platform.Firewall{Run: s.run}); err != nil {
		t.Fatal(err)
	}
	m, _ = loadHost(p)
	if m.PendingFirewall != nil || !s.rules["any 24441 nodekit:tcp:24441"] {
		t.Fatal("retry failed", m, s.rules)
	}
}

func TestFirewallJournalCommitFailureRetryAndDNSPreservation(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	commit, _, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
	if err != nil {
		t.Fatal(err)
	}
	// Make the durable commit fail without changing the real firewall or
	// losing the original pending journal used for the retry.
	if err = os.Rename(filepath.Join(p.Etc, "host.json"), filepath.Join(p.Etc, "saved-host.json")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(p.Etc, "host.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = commit(); err == nil {
		t.Fatal("manifest commit failure swallowed")
	}
	if err = os.Remove(filepath.Join(p.Etc, "host.json")); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(p.Etc, "saved-host.json"), filepath.Join(p.Etc, "host.json")); err != nil {
		t.Fatal(err)
	}
	m, _ := loadHost(p)
	if m.PendingFirewall == nil {
		t.Fatal("pending journal missing")
	}
	m.InstallationID = "concurrent-owner"
	m.DNSRecords = []cloudflare.ManagedRecord{{ZoneID: "z", Record: cloudflare.Record{ID: "record"}}}
	if err = saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	if err = commit(); err != nil {
		t.Fatal(err)
	}
	got, _ := loadHost(p)
	if got.PendingFirewall != nil || got.InstallationID != "concurrent-owner" || !reflect.DeepEqual(got.DNSRecords, m.DNSRecords) {
		t.Fatal("DNS fields overwritten", got)
	}
	if !reflect.DeepEqual(got.Firewall, platform.Bindings(next)) {
		t.Fatal(got.Firewall)
	}
}

func TestRememberFirewallIntentPreservesLegacyAndPending(t *testing.T) {
	c, _ := model.New()
	legacy := platform.Binding{Network: "tcp", Port: 24441, IPv6: true}
	pending := &firewallOperation{Old: []platform.Binding{legacy}, New: []platform.Binding{{Network: "tcp", Port: 24442}}, Revision: 1}
	m := hostManifest{Firewall: []platform.Binding{legacy}, PendingFirewall: pending}
	rememberFirewallIntent(&m, c)
	if m.PendingFirewall != pending || m.Firewall[0] != legacy {
		t.Fatal("recovery intent discarded", m)
	}
	m.PendingFirewall = nil
	rememberFirewallIntent(&m, c)
	if m.PendingFirewall == nil || m.PendingFirewall.Old[0] != legacy {
		t.Fatal("missing durable transition", m)
	}
}

func TestFirewallApplyDoesNotReplayRawRecoveryUnion(t *testing.T) {
	old := []platform.Binding{{Network: "tcp", Port: 24441, IPv6: true}}
	next := []platform.Binding{{Network: "tcp", Port: 24441, Family: "ipv4"}}
	m := hostManifest{Firewall: old, PendingFirewall: &firewallOperation{Old: old, New: next}}
	if got := firewallApplyBindings(m); !reflect.DeepEqual(got, next) {
		t.Fatal("apply resurrects legacy generic IPv6", got)
	}
	m.PendingFirewall = nil
	if got := firewallApplyBindings(m); !reflect.DeepEqual(got, old) {
		t.Fatal(got)
	}
}

func TestFirewallApplyFailureCompensatesAndAbortCanRetry(t *testing.T) {
	t.Run("apply compensation", func(t *testing.T) {
		p, old, next, s := transactionFixture(t)
		s.fail = "to ::/0"
		_, _, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
		if err == nil {
			t.Fatal("IPv6 insertion failure swallowed")
		}
		m, _ := loadHost(p)
		if m.PendingFirewall != nil || len(s.rules) != 2 || !s.rules["any 24441 nodekit:tcp:24441"] {
			t.Fatal("old physical ownership not compensated", m, s.rules)
		}
	})
	t.Run("abort retry", func(t *testing.T) {
		p, old, next, s := transactionFixture(t)
		_, abort, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
		if err != nil {
			t.Fatal(err)
		}
		s.fail = "ufw --force delete allow proto tcp from any to ::/0"
		if err = abort(); err == nil {
			t.Fatal("abort failure swallowed")
		}
		m, _ := loadHost(p)
		if m.PendingFirewall == nil {
			t.Fatal("failed abort cleared journal")
		}
		s.fail = ""
		if err = abort(); err != nil {
			t.Fatal(err)
		}
		m, _ = loadHost(p)
		if m.PendingFirewall != nil || len(s.rules) != 2 || !s.rules["any 24441 nodekit:tcp:24441"] {
			t.Fatal("abort retry failed", m, s.rules)
		}
	})
}

func TestFirewallCommitBackendFailureLeavesJournalForRetry(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	commit, _, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
	if err != nil {
		t.Fatal(err)
	}
	s.fail = "ufw show added"
	if err = commit(); err == nil {
		t.Fatal("backend observation failure swallowed")
	}
	m, _ := loadHost(p)
	if m.PendingFirewall == nil {
		t.Fatal("uncertain commit cleared journal")
	}
	s.fail = ""
	if err = commit(); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallChangeUsesManifestOwnershipNotOldModelReconstruction(t *testing.T) {
	p, old, next, s := transactionFixture(t)
	m, _ := loadHost(p)
	m.Firewall = []platform.Binding{{Network: "tcp", Port: 24446}, {Network: "tcp", Port: 25000}}
	if err := saveHost(p, m); err != nil {
		t.Fatal(err)
	}
	s.rules["any 25000 nodekit:tcp:25000"] = true
	for i := range next.Protocols {
		next.Protocols[i].Enabled = next.Protocols[i].Type == "anytls"
	}
	next.IPv6Nodes.Protocols = []string{"anytls"}
	_, abort, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run})
	if err != nil {
		t.Fatal(err)
	}
	if s.rules["any 25000 nodekit:tcp:25000"] {
		t.Fatal("manifest-owned obsolete rule ignored")
	}
	if !s.rules["any 24441 nodekit:tcp:24441"] {
		t.Fatal("model reconstruction claimed an unmanifested physical rule")
	}
	if err = abort(); err != nil {
		t.Fatal(err)
	}
	if !s.rules["any 25000 nodekit:tcp:25000"] {
		t.Fatal("abort lost manifest-only provenance")
	}
}

func TestFirewallRecoveryNewIntentIsQualifiedAndCommittedRevisionUsesNew(t *testing.T) {
	t.Run("new init intent", func(t *testing.T) {
		p, old, _, s := transactionFixture(t)
		s.rules = map[string]bool{}
		m := hostManifest{PendingFirewall: &firewallOperation{New: platform.Bindings(old), Revision: old.Revision}}
		if err := saveHost(p, m); err != nil {
			t.Fatal(err)
		}
		if _, err := reconcileFirewallWith(context.Background(), p, m, old, platform.Firewall{Run: s.run}); err != nil {
			t.Fatal(err)
		}
		if len(s.rules) != 2 || !s.rules["0.0.0.0/0 24441 nodekit:tcp:24441"] || !s.rules["0.0.0.0/0 24446 nodekit:tcp:24446"] {
			t.Fatal("recovery created generic new rules", s.rules)
		}
	})
	t.Run("committed config revision", func(t *testing.T) {
		p, old, next, s := transactionFixture(t)
		if _, _, err := beginFirewallChangeWith(context.Background(), p, old, next, platform.Firewall{Run: s.run}); err != nil {
			t.Fatal(err)
		}
		next.Revision++
		m, _ := loadHost(p)
		got, err := reconcileFirewallWith(context.Background(), p, m, next, platform.Firewall{Run: s.run})
		if err != nil {
			t.Fatal(err)
		}
		if got.PendingFirewall != nil || !reflect.DeepEqual(got.Firewall, platform.Bindings(next)) || s.rules["any 24441 nodekit:tcp:24441"] {
			t.Fatal("new config recovered as old", got, s.rules)
		}
	})
}
