package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFirewallPreflightIsReadOnlyAndFamilyAware(t *testing.T) {
	for _, tc := range []struct {
		name, backend                   string
		ipv6, missing6, denied, wantErr bool
	}{
		{"IPv4 tables", "iptables", false, false, false, false},
		{"dual tables", "iptables", true, false, false, false},
		{"missing IPv6 tables", "iptables", true, true, false, true},
		{"tables permission failure", "iptables", false, false, true, true},
		{"unsupported", "none", false, false, false, true},
		{"UFW IPv4", "ufw", false, false, false, false},
		{"UFW dual", "ufw", true, false, false, false},
		{"UFW IPv6 disabled", "ufw", true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Firewall{Run: func(ctx context.Context, args ...string) ([]byte, error) {
				cmd := strings.Join(args, " ")
				switch {
				case cmd == "ufw status":
					if tc.backend == "ufw" {
						return []byte("Status: active\n"), nil
					}
					return nil, errors.New("ufw unavailable")
				case cmd == "ufw show added":
					return []byte("Added user rules (see 'ufw status' for running firewall):\n"), nil
				case strings.HasPrefix(cmd, "ufw --dry-run allow "):
					if tc.missing6 {
						return []byte("Skipping adding rule (IPv6 disabled)"), nil
					}
					return []byte("*filter\nCOMMIT\n"), nil
				case len(args) > 1 && (args[0] == "iptables" || args[0] == "ip6tables") && (args[1] == "-S" || args[1] == "-C"):
					if tc.backend != "iptables" || args[0] == "ip6tables" && tc.missing6 {
						return nil, errors.New("backend unavailable")
					}
					if tc.denied {
						return nil, firewallExitError(4)
					}
					if args[1] == "-C" {
						return nil, firewallExitError(1)
					}
					return []byte("-P INPUT DROP\n"), nil
				default:
					t.Errorf("unexpected or mutating preflight command: %s", cmd)
					return nil, fmt.Errorf("unexpected command")
				}
			}}
			err := f.Preflight(context.Background(), []Binding{{Network: "tcp", Port: 24441, IPv6: tc.ipv6}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("got %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestFirewallPreflightRejectsUnusableOwnedUFWRule(t *testing.T) {
	f := Firewall{Run: func(_ context.Context, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "ufw status":
			return []byte("Status: active\n"), nil
		case "ufw show added":
			return []byte("ufw allow proto tcp from any to 0.0.0.0/0 port 24441 comment 'nodekit:tcp:24441'\n"), nil
		default:
			t.Fatal("preflight attempted mutation", args)
			return nil, nil
		}
	}}
	if err := f.Preflight(context.Background(), []Binding{{Network: "tcp", Port: 24441}}); err == nil {
		t.Fatal("accepted stored UFW rule with no live family allowance")
	}
}
