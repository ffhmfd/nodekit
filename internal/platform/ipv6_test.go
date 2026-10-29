package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"nodekit/internal/model"
	"reflect"
	"strings"
	"testing"
)

func TestBindingJSONFamiliesAndValidation(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		families []string
	}{
		{`{"network":"tcp","port":24441,"ipv6":false}`, []string{"ipv4"}},
		{`{"network":"tcp","port":24441,"ipv6":true}`, []string{"ipv4", "ipv6"}},
		{`{"network":"tcp","port":24441,"ipv6":false,"family":"ipv6","address":"2606:4700::1111"}`, []string{"ipv6"}},
	} {
		var b Binding
		if err := json.Unmarshal([]byte(tc.raw), &b); err != nil {
			t.Fatal(err)
		}
		got := CoverageDifference([]Binding{b}, nil)
		var families []string
		for _, v := range got {
			families = append(families, v.Family)
		}
		if !reflect.DeepEqual(families, tc.families) {
			t.Fatalf("%s: %v", tc.raw, got)
		}
		encoded, _ := json.Marshal(b)
		if b.Family == "" && strings.Contains(string(encoded), "family") {
			t.Fatal(string(encoded))
		}
	}
	f := Firewall{Run: func(context.Context, ...string) ([]byte, error) {
		t.Fatal("invalid binding reached runner")
		return nil, nil
	}}
	for _, b := range []Binding{
		{Network: "tcp", Port: 24441, Family: "bad"},
		{Network: "tcp", Port: 24441, Family: "ipv6", IPv6: true},
		{Network: "tcp", Port: 24441, Family: "ipv4", Address: "::1"},
	} {
		if err := f.Apply(context.Background(), []Binding{b}); err == nil {
			t.Fatal("accepted", b)
		}
	}
	got := CoverageDifference([]Binding{{Network: "tcp", Port: 24441, IPv6: true}}, []Binding{{Network: "tcp", Port: 24441}})
	if len(got) != 1 || got[0].Family != "ipv6" {
		t.Fatal("dual minus v4", got)
	}
}

func TestBindingsPreserveSubscriptionAndListenerAddresses(t *testing.T) {
	c, _ := model.New()
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2606:4700::1111", Protocols: []string{"ss", "tuic"}, IPv4ListenAddresses: []string{"127.0.0.1", "127.0.0.2"}}
	for i := range c.Protocols {
		c.Protocols[i].Enabled = c.Protocols[i].Type == "ss"
	}
	got := Bindings(c)
	want := []Binding{
		{Network: "tcp", Port: 24446},
		{Network: "tcp", Port: 24442, Family: "ipv4", Address: "127.0.0.1"}, {Network: "udp", Port: 24442, Family: "ipv4", Address: "127.0.0.1"},
		{Network: "tcp", Port: 24442, Family: "ipv4", Address: "127.0.0.2"}, {Network: "udp", Port: 24442, Family: "ipv4", Address: "127.0.0.2"},
		{Network: "tcp", Port: 24442, Family: "ipv6", Address: "2606:4700::1111"}, {Network: "udp", Port: 24442, Family: "ipv6", Address: "2606:4700::1111"},
		{Network: "udp", Port: 24443, Family: "ipv6", Address: "2606:4700::1111"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bindings: %#v", got)
	}
}

func TestCheckPortsUsesActualFamilyAddressAndMigrationAllowance(t *testing.T) {
	c, _ := model.New()
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2606:4700::1111", Protocols: []string{"ss"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	for i := range c.Protocols {
		c.Protocols[i].Enabled = c.Protocols[i].Type == "ss"
	}
	var probes []string
	probe := func(network, address string) error { probes = append(probes, network+" "+address); return nil }
	old := []Binding{{Network: "tcp", Port: 24446}, {Network: "tcp", Port: 24442, Family: "ipv4", Address: "127.0.0.1"}, {Network: "udp", Port: 24442, Family: "ipv4", Address: "127.0.0.1"}}
	if err := checkPorts(c, old, probe); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(probes, []string{"tcp6 [2606:4700::1111]:24442", "udp6 [2606:4700::1111]:24442"}) {
		t.Fatal(probes)
	}
	if err := checkPorts(c, old, func(string, string) error { return errors.New("occupied") }); err == nil {
		t.Fatal("opposite-family ownership hid a new conflict")
	}
	probes = nil
	c.IPv6Nodes.IPv4ListenAddresses = []string{"127.0.0.2"}
	if err := checkPorts(c, old, probe); err != nil {
		t.Fatal(err)
	}
	if probes[0] != "tcp4 127.0.0.2:24442" {
		t.Fatal("changed address was not checked", probes)
	}
	probes = nil
	legacy := []Binding{{Network: "tcp", Port: 24446}, {Network: "tcp", Port: 24442}, {Network: "udp", Port: 24442}}
	if err := checkPorts(c, legacy, probe); err != nil || len(probes) != 0 {
		t.Fatal("owned legacy wildcard rebound", probes, err)
	}
}

// The fake models exact physical identities, including UFW coalescing and a
// disabled IPv6 backend. No test invokes the host firewall.
type familyFirewall struct {
	ufw        bool
	rules      map[string]bool
	fail       string
	skip6      bool
	shortAdded bool
	commands   []string
}

type firewallExitError int

func (e firewallExitError) Error() string { return fmt.Sprintf("firewall exit %d", e) }
func (e firewallExitError) ExitCode() int { return int(e) }

func (s *familyFirewall) run(_ context.Context, args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	s.commands = append(s.commands, cmd)
	if s.fail != "" && strings.Contains(cmd, s.fail) {
		return nil, errors.New("injected failure")
	}
	if cmd == "ufw status" {
		if !s.ufw {
			return []byte("Status: inactive"), nil
		}
		var out strings.Builder
		out.WriteString("Status: active\nTo Action From\n-- ------ ----\n")
		for rule := range s.rules {
			fields := strings.Fields(rule)
			if len(fields) != 4 {
				continue
			}
			net, port, to, tag := fields[0], fields[1], fields[2], fields[3]
			if to != "::/0" {
				fmt.Fprintf(&out, "%s/%s ALLOW Anywhere # %s\n", port, net, tag)
			}
			if (to == "any" || to == "::/0") && !s.skip6 {
				fmt.Fprintf(&out, "%s/%s (v6) ALLOW Anywhere (v6) # %s\n", port, net, tag)
			}
		}
		return []byte(out.String()), nil
	}
	if cmd == "ufw show added" {
		var out strings.Builder
		for rule := range s.rules {
			p := strings.Fields(rule)
			if len(p) == 4 {
				if s.shortAdded {
					fmt.Fprintf(&out, "ufw allow %s/%s comment '%s'\n", p[1], p[0], p[3])
				} else {
					fmt.Fprintf(&out, "ufw allow proto %s from any to %s port %s comment '%s'\n", p[0], p[2], p[1], p[3])
				}
			}
		}
		return []byte(out.String()), nil
	}
	if args[0] == "ufw" {
		remove := len(args) > 2 && args[1] == "--force"
		value := func(key string) string {
			for i := 0; i < len(args)-1; i++ {
				if args[i] == key {
					return args[i+1]
				}
			}
			return ""
		}
		net, port, to, tag := value("proto"), value("port"), value("to"), value("comment")
		if net == "" || port == "" || to == "" || tag == "" {
			return nil, fmt.Errorf("unexpected UFW command %s", cmd)
		}
		key := strings.Join([]string{net, port, to, tag}, " ")
		if remove {
			// UFW matches normalized packet identities, not the original CLI
			// spelling. A generic delete can remove qualified halves, and a
			// qualified delete removes only its half of a generic definition.
			for existing := range s.rules {
				p := strings.Fields(existing)
				if len(p) != 4 || p[0] != net || p[1] != port || p[3] != tag {
					continue
				}
				if to == "any" || p[2] == to {
					delete(s.rules, existing)
					continue
				}
				if p[2] == "any" {
					delete(s.rules, existing)
					if to == "0.0.0.0/0" && !s.skip6 {
						s.rules[strings.Join([]string{net, port, "::/0", tag}, " ")] = true
					}
					if to == "::/0" {
						s.rules[strings.Join([]string{net, port, "0.0.0.0/0", tag}, " ")] = true
					}
				}
			}
			return nil, nil
		}
		for existing := range s.rules {
			p := strings.Fields(existing)
			if len(p) == 4 && p[0] == net && p[1] == port && (p[2] == to || p[2] == "any" || to == "any") {
				return []byte("Skipping adding existing rule"), nil
			}
		}
		s.rules[key] = true
		return nil, nil
	}
	if cmd == "iptables -S INPUT" {
		return nil, nil
	}
	if len(args) < 4 {
		return nil, fmt.Errorf("unexpected command %s", cmd)
	}
	key := args[0] + " " + strings.Join(args[3:], " ")
	if args[1] == "-I" {
		key = args[0] + " " + strings.Join(args[4:], " ")
	}
	switch args[1] {
	case "-C":
		if !s.rules[key] {
			return nil, firewallExitError(1)
		}
	case "-I":
		s.rules[key] = true
	case "-D":
		delete(s.rules, key)
	default:
		return nil, fmt.Errorf("unexpected command %s", cmd)
	}
	return nil, nil
}

func TestFirewallSharedPortTransitionsKeepIPv4(t *testing.T) {
	for _, ufw := range []bool{false, true} {
		t.Run(fmt.Sprint(ufw), func(t *testing.T) {
			s := &familyFirewall{ufw: ufw, rules: map[string]bool{}}
			f := Firewall{Run: s.run}
			v4 := Binding{Network: "tcp", Port: 24441, Family: "ipv4", Address: "127.0.0.1"}
			v6 := Binding{Network: "tcp", Port: 24441, Family: "ipv6", Address: "2606:4700::1111"}
			if err := f.Apply(context.Background(), []Binding{v4}); err != nil {
				t.Fatal(err)
			}
			if err := f.Reconcile(context.Background(), []Binding{v4}, []Binding{v4, v6}); err != nil {
				t.Fatal(err)
			}
			if len(s.rules) != 2 {
				t.Fatal(s.rules)
			}
			if err := f.Reconcile(context.Background(), []Binding{v4, v6}, []Binding{v4}); err != nil {
				t.Fatal(err)
			}
			if len(s.rules) != 1 {
				t.Fatal("v6 disable removed IPv4", s.rules)
			}
			for rule := range s.rules {
				if ufw && !strings.Contains(rule, "0.0.0.0/0") || !ufw && !strings.HasPrefix(rule, "iptables ") {
					t.Fatal(rule)
				}
			}
		})
	}
}

func TestUFWGenericMigrationRollbackAndPhysicalSnapshot(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{"tcp 24441 any nodekit:tcp:24441": true}}
	f := Firewall{Run: s.run}
	old := []Binding{{Network: "tcp", Port: 24441}}
	snapshot, err := f.Snapshot(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 2 || !snapshot[1].IPv6 {
		t.Fatal("lost physical generic IPv6 provenance", snapshot)
	}
	next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv4"}}
	if err = f.Reconcile(context.Background(), snapshot, next); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:ipv4:tcp:24441"] {
		t.Fatal("generic not migrated", s.rules)
	}
	if err = f.Restore(context.Background(), append(snapshot, next...), snapshot); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 any nodekit:tcp:24441"] {
		t.Fatal("abort did not restore generic", s.rules)
	}
	if err = f.Remove(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err = f.Remove(context.Background(), snapshot); err != nil || len(s.rules) != 0 {
		t.Fatal("cleanup not idempotent", s.rules, err)
	}
}

func TestUFWDoesNotAdoptForeignCoalescedOrSkippedIPv6(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		skip6      bool
	}{
		{"foreign equivalent", "tcp 24441 0.0.0.0/0 foreign", false},
		{"tag on wrong protocol", "udp 24441 0.0.0.0/0 nodekit:ipv4:tcp:24441", false},
		{"ipv6 disabled", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &familyFirewall{ufw: true, skip6: tc.skip6, rules: map[string]bool{}}
			if tc.rule != "" {
				s.rules[tc.rule] = true
			}
			b := Binding{Network: "tcp", Port: 24441, Family: "ipv4"}
			if tc.skip6 {
				b.Family = "ipv6"
			}
			f := Firewall{Run: s.run}
			err := f.Apply(context.Background(), []Binding{b})
			if tc.name == "tag on wrong protocol" {
				if err != nil || len(s.rules) != 2 {
					t.Fatal(s.rules, err)
				}
			} else if err == nil {
				t.Fatal("unverified allowance accepted", s.rules)
			}
			if tc.name == "foreign equivalent" {
				for _, cmd := range s.commands {
					if strings.HasPrefix(cmd, "ufw allow ") {
						t.Fatal("insertion could relabel a foreign equivalent", cmd)
					}
				}
			}
			if err = f.Remove(context.Background(), []Binding{b}); err != nil {
				t.Fatal(err)
			}
			if tc.rule != "" && !s.rules[tc.rule] {
				t.Fatal("foreign/mismatched rule removed", s.rules)
			}
		})
	}
}

func TestUFWCanonicalShortAddedStillTracksPhysicalFamily(t *testing.T) {
	s := &familyFirewall{ufw: true, shortAdded: true, rules: map[string]bool{"tcp 24441 any nodekit:tcp:24441": true}}
	f := Firewall{Run: s.run}
	old := []Binding{{Network: "tcp", Port: 24441}}
	next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv4"}, {Network: "tcp", Port: 24441, Family: "ipv6"}}
	if err := f.Reconcile(context.Background(), old, next); err != nil {
		t.Fatal("UFW reconstructs wildcard commands using short syntax", err)
	}
	if err := f.Reconcile(context.Background(), next, next[:1]); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:ipv4:tcp:24441"] {
		t.Fatal("v6 disable lost physical IPv4", s.rules)
	}
}

func TestUFWPhysicalOwnershipRequiresExactAllowFromToAndProtocol(t *testing.T) {
	r := ufwRule{network: "tcp", port: 24441, to: "0.0.0.0/0", tag: "nodekit:ipv4:tcp:24441"}
	for _, line := range []string{
		"244410/tcp ALLOW Anywhere # nodekit:ipv4:tcp:24441",
		"24441/udp ALLOW Anywhere # nodekit:ipv4:tcp:24441",
		"24441/tcp DENY Anywhere # nodekit:ipv4:tcp:24441",
		"24441/tcp ALLOW OUT Anywhere # nodekit:ipv4:tcp:24441",
		"24441/tcp ALLOW 192.0.2.1 # nodekit:ipv4:tcp:24441",
		"24441/tcp 192.0.2.1 ALLOW Anywhere # nodekit:ipv4:tcp:24441",
		"24441/tcp (v6) ALLOW Anywhere (v6) # nodekit:ipv4:tcp:24441",
	} {
		if ufwPhysical(line, r, "ipv4") {
			t.Fatal("foreign physical identity accepted", line)
		}
	}
	for _, line := range []string{
		"ufw deny 24441/tcp comment 'nodekit:ipv4:tcp:24441'",
		"ufw allow proto tcp from 192.0.2.1 to 0.0.0.0/0 port 24441 comment 'nodekit:ipv4:tcp:24441'",
		"ufw allow proto tcp from any to 192.0.2.1 port 24441 comment 'nodekit:ipv4:tcp:24441'",
	} {
		if parseUFWAdded(line)[r] {
			t.Fatal("foreign stored identity accepted", line)
		}
	}
}

func TestIPTablesLegacyCommentReuseAndOppositeFamilyCleanup(t *testing.T) {
	const v4 = "iptables -p tcp --dport 24441 -m comment --comment nodekit:tcp:24441 -j ACCEPT"
	const v6 = "ip6tables -p tcp --dport 24441 -m comment --comment nodekit:tcp:24441 -j ACCEPT"
	const foreign = "ip6tables -p tcp --dport 24441 -m comment --comment foreign -j ACCEPT"
	s := &familyFirewall{rules: map[string]bool{v4: true, v6: true, foreign: true}}
	f := Firewall{Run: s.run}
	old := []Binding{{Network: "tcp", Port: 24441, IPv6: true}}
	next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv4", Address: "127.0.0.1"}, {Network: "tcp", Port: 24441, Family: "ipv4", Address: "127.0.0.2"}}
	if err := f.Reconcile(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 2 || !s.rules[v4] || !s.rules[foreign] {
		t.Fatal("IPv4 was deleted or legacy tag not reused", s.rules)
	}
	if err := f.Remove(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules[foreign] {
		t.Fatal("foreign rule removed", s.rules)
	}
	if err := f.Remove(context.Background(), append(old, next...)); err != nil {
		t.Fatal(err)
	}
}

func TestUFWIPv6OnlyCreatesNoIPv4Allowance(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{}}
	f := Firewall{Run: s.run}
	b := []Binding{{Network: "udp", Port: 24443, Family: "ipv6", Address: "2606:4700::1111"}}
	if err := f.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["udp 24443 ::/0 nodekit:ipv6:udp:24443"] {
		t.Fatal(s.rules)
	}
}

func TestIPTablesUncertainInspectionOrMutationCannotReportSuccess(t *testing.T) {
	for _, failure := range []string{"inspect", "insert", "delete"} {
		t.Run(failure, func(t *testing.T) {
			s := &familyFirewall{rules: map[string]bool{}}
			if failure == "delete" {
				s.rules["iptables -p tcp --dport 24441 -m comment --comment nodekit:tcp:24441 -j ACCEPT"] = true
			}
			f := Firewall{Run: func(ctx context.Context, args ...string) ([]byte, error) {
				if len(args) > 1 && args[0] == "iptables" {
					if failure == "inspect" && args[1] == "-C" {
						return nil, firewallExitError(2)
					}
					if failure == "insert" && args[1] == "-I" || failure == "delete" && args[1] == "-D" {
						return nil, nil
					}
				}
				return s.run(ctx, args...)
			}}
			b := []Binding{{Network: "tcp", Port: 24441}}
			var err error
			if failure == "delete" {
				err = f.Remove(context.Background(), b)
			} else {
				err = f.Apply(context.Background(), b)
			}
			if err == nil {
				t.Fatal("uncertain physical state reported success", failure, s.rules)
			}
		})
	}
}

func TestUFWNewLegacyIntentUsesQualifiedRulesAndSnapshotKeepsIdentity(t *testing.T) {
	s := &familyFirewall{ufw: true, rules: map[string]bool{}}
	f := Firewall{Run: s.run}
	legacy := []Binding{{Network: "tcp", Port: 24441}}
	if err := f.Apply(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:tcp:24441"] {
		t.Fatal("new legacy intent created an unqualified allowance", s.rules)
	}
	snapshot, err := f.Snapshot(context.Background(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != 2 || snapshot[0] != legacy[0] || snapshot[1].Family != "ipv4" {
		t.Fatal("qualified physical provenance not retained", snapshot)
	}
	next := []Binding{{Network: "tcp", Port: 24441, Family: "ipv6"}}
	if err = f.Reconcile(context.Background(), snapshot, next); err != nil {
		t.Fatal(err)
	}
	s.rules["tcp 24441 any nodekit:tcp:24441"] = true
	if err = f.Restore(context.Background(), append(snapshot, next...), snapshot); err != nil {
		t.Fatal(err)
	}
	if len(s.rules) != 1 || !s.rules["tcp 24441 0.0.0.0/0 nodekit:tcp:24441"] {
		t.Fatal("abort broadened qualified old ownership into generic", s.rules)
	}
}
