package cli

import (
	"context"
	"errors"
	"fmt"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"os"
	"strings"
	"testing"
)

type recoveryExit int

func (e recoveryExit) Error() string { return fmt.Sprintf("exit %d", e) }
func (e recoveryExit) ExitCode() int { return int(e) }

func TestFirewallRecoveryDoesNotPromoteStagedLegacyDualIntoOld(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ufw, marker bool
	}{
		{"iptables", false, false}, {"qualified UFW raw Old", true, false}, {"qualified UFW snapshotted Old", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makePaths(t.TempDir(), "")
			if err := os.MkdirAll(p.Etc, 0700); err != nil {
				t.Fatal(err)
			}
			c, _ := model.New()
			for i := range c.Protocols {
				c.Protocols[i].Enabled = false
			}
			old := []platform.Binding{{Network: "tcp", Port: 24446}}
			if tc.marker {
				old = append(old, platform.Binding{Network: "tcp", Port: 24446, Family: "ipv4"})
			}
			next := []platform.Binding{{Network: "tcp", Port: 24446, IPv6: true}}
			m := hostManifest{Firewall: old, PendingFirewall: &firewallOperation{Old: old, New: next, Revision: c.Revision}}
			if err := saveHost(p, m); err != nil {
				t.Fatal(err)
			}
			rules := map[string]bool{}
			var run platform.Runner
			if tc.ufw {
				s := &journalFirewall{rules: map[string]bool{"0.0.0.0/0 24446 nodekit:ipv4:tcp:24446": true, "::/0 24446 nodekit:ipv6:tcp:24446": true}}
				rules = s.rules
				run = s.run
			} else {
				rules["iptables -p tcp --dport 24446 -m comment --comment nodekit:tcp:24446 -j ACCEPT"] = true
				rules["ip6tables -p tcp --dport 24446 -m comment --comment nodekit:tcp:24446 -j ACCEPT"] = true
				run = func(_ context.Context, args ...string) ([]byte, error) {
					cmd := strings.Join(args, " ")
					if cmd == "ufw status" {
						return []byte("Status: inactive"), nil
					}
					if cmd == "iptables -S INPUT" {
						return nil, nil
					}
					key := args[0] + " " + strings.Join(args[3:], " ")
					if args[1] == "-I" {
						key = args[0] + " " + strings.Join(args[4:], " ")
					}
					switch args[1] {
					case "-C":
						if !rules[key] {
							return nil, recoveryExit(1)
						}
					case "-I":
						rules[key] = true
					case "-D":
						delete(rules, key)
					default:
						return nil, fmt.Errorf("unexpected command %s", cmd)
					}
					return nil, nil
				}
			}
			// A failed physical update must not durably contaminate Old either.
			failedRun := func(ctx context.Context, args ...string) ([]byte, error) {
				cmd := strings.Join(args, " ")
				if strings.Contains(cmd, " -D ") || strings.Contains(cmd, "ufw --force delete") {
					return nil, errors.New("injected recovery deletion failure")
				}
				return run(ctx, args...)
			}
			if _, err := reconcileFirewallWith(context.Background(), p, m, c, platform.Firewall{Run: failedRun}); err == nil {
				t.Fatal("failed recovery reported success")
			}
			m, err := loadHost(p)
			if err != nil || m.PendingFirewall == nil {
				t.Fatal("failed recovery lost journal", err)
			}
			for _, b := range m.PendingFirewall.Old {
				if b.IPv6 || b.Family == "ipv6" {
					t.Fatal("failed recovery polluted durable Old", m.PendingFirewall.Old)
				}
			}
			got, err := reconcileFirewallWith(context.Background(), p, m, c, platform.Firewall{Run: run})
			if err != nil {
				t.Fatal(err)
			}
			if got.PendingFirewall != nil {
				t.Fatal("recovery not completed")
			}
			for _, b := range got.Firewall {
				if b.IPv6 || b.Family == "ipv6" {
					t.Fatal("New intent promoted into committed Old", got.Firewall)
				}
			}
			for rule := range rules {
				if strings.HasPrefix(rule, "ip6tables ") || strings.HasPrefix(rule, "::/0 ") {
					t.Fatal("staged IPv6 physical allowance survived old-config recovery", rules)
				}
			}
		})
	}
}

func TestFirewallNoPendingStartupPreservesLegacyGenericRules(t *testing.T) {
	p, _, _, s := transactionFixture(t)
	m, err := loadHost(p)
	if err != nil || m.PendingFirewall != nil {
		t.Fatal("fixture must have no pending journal", err)
	}
	s.fail = "ufw allow"
	if err = (platform.Firewall{Run: s.run}).Apply(context.Background(), firewallApplyBindings(m)); err != nil {
		t.Fatal("no-pending startup tried replacing an existing allowance", err)
	}
	if len(s.rules) != 2 || !s.rules["any 24441 nodekit:tcp:24441"] || !s.rules["any 24446 nodekit:tcp:24446"] {
		t.Fatal("no-pending startup removed required ownership", s.rules)
	}
	got, err := loadHost(p)
	if err != nil || got.PendingFirewall != nil {
		t.Fatal("ensure-only startup manufactured a pending journal", err)
	}
}
