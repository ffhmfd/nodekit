package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type ipv6JSONSettings struct {
	Enabled             bool     `json:"enabled"`
	Address             string   `json:"address"`
	Protocols           []string `json:"protocols"`
	IPv4ListenAddresses []string `json:"ipv4_listen_addresses"`
}

func ipv6JSONFixture(t *testing.T, enabled bool) Config {
	t.Helper()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	c.Address = "8.8.8.8"
	return withIPv6JSON(t, c, ipv6JSONSettings{
		Enabled:             enabled,
		Address:             "2001:4860:4860::8888",
		Protocols:           []string{"vless", "tuic"},
		IPv4ListenAddresses: []string{"10.0.0.2", "127.0.0.1"},
	})
}

func withIPv6JSON(t *testing.T, c Config, settings ipv6JSONSettings) Config {
	t.Helper()
	data, err := json.Marshal(map[string]ipv6JSONSettings{"ipv6_nodes": settings})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIPv6JSONRoundTripPreservesSavedSettings(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "off", true: "on"}[enabled], func(t *testing.T) {
			c := ipv6JSONFixture(t, enabled)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]json.RawMessage
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			var got ipv6JSONSettings
			if err := json.Unmarshal(saved["ipv6_nodes"], &got); err != nil {
				t.Fatalf("ipv6_nodes was not preserved: %v", err)
			}
			want := ipv6JSONSettings{enabled, "2001:4860:4860::8888", []string{"vless", "tuic"}, []string{"10.0.0.2", "127.0.0.1"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("saved settings = %+v, want %+v", got, want)
			}
		})
	}
}

func TestIPv6JSONRejectsInvalidSettingsEvenWhenOff(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ipv6JSONSettings)
	}{
		{"empty address", func(s *ipv6JSONSettings) { s.Address = "" }},
		{"IPv4 address", func(s *ipv6JSONSettings) { s.Address = "8.8.8.8" }},
		{"mapped address", func(s *ipv6JSONSettings) { s.Address = "::ffff:8.8.8.8" }},
		{"zone", func(s *ipv6JSONSettings) { s.Address = "2001:4860::1%eth0" }},
		{"bracketed address", func(s *ipv6JSONSettings) { s.Address = "[2001:4860::1]" }},
		{"unspecified", func(s *ipv6JSONSettings) { s.Address = "::" }},
		{"loopback", func(s *ipv6JSONSettings) { s.Address = "::1" }},
		{"ULA", func(s *ipv6JSONSettings) { s.Address = "fd00::1" }},
		{"link local", func(s *ipv6JSONSettings) { s.Address = "fe80::1" }},
		{"multicast", func(s *ipv6JSONSettings) { s.Address = "ff02::1" }},
		{"outside global allocation", func(s *ipv6JSONSettings) { s.Address = "4000::1" }},
		{"reserved", func(s *ipv6JSONSettings) { s.Address = "2001:1ff::1" }},
		{"documentation", func(s *ipv6JSONSettings) { s.Address = "2001:db8::1" }},
		{"6to4", func(s *ipv6JSONSettings) { s.Address = "2002::1" }},
		{"new documentation", func(s *ipv6JSONSettings) { s.Address = "3fff::1" }},
		{"noncanonical IPv6", func(s *ipv6JSONSettings) { s.Address = "2001:4860:4860:0:0:0:0:8888" }},
		{"uppercase IPv6", func(s *ipv6JSONSettings) { s.Address = "2A00:1450::1" }},
		{"empty protocol selection", func(s *ipv6JSONSettings) { s.Protocols = nil }},
		{"duplicate protocol", func(s *ipv6JSONSettings) { s.Protocols = []string{"vless", "vless"} }},
		{"unknown protocol", func(s *ipv6JSONSettings) { s.Protocols = []string{"unknown"} }},
		{"empty IPv4 bindings", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = nil }},
		{"duplicate IPv4 binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"10.0.0.2", "10.0.0.2"} }},
		{"unspecified IPv4 binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"0.0.0.0"} }},
		{"multicast IPv4 binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"224.0.0.1"} }},
		{"mapped IPv4 binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"::ffff:10.0.0.2"} }},
		{"IPv6 binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"2001:4860::1"} }},
		{"nonliteral binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"localhost"} }},
		{"noncanonical IPv4", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{"010.0.0.2"} }},
		{"whitespace binding", func(s *ipv6JSONSettings) { s.IPv4ListenAddresses = []string{" 10.0.0.2"} }},
	}
	for _, enabled := range []bool{false, true} {
		for _, tt := range tests {
			t.Run(map[bool]string{false: "off/", true: "on/"}[enabled]+tt.name, func(t *testing.T) {
				c, err := New()
				if err != nil {
					t.Fatal(err)
				}
				c.Address = "8.8.8.8"
				s := ipv6JSONSettings{enabled, "2001:4860:4860::8888", []string{"vless"}, []string{"10.0.0.2"}}
				tt.mutate(&s)
				c = withIPv6JSON(t, c, s)
				if err := c.Validate(); err == nil {
					t.Fatal("accepted invalid ipv6_nodes settings")
				}
			})
		}
	}
}

func TestIPv6JSONRequiresIPv4Installation(t *testing.T) {
	for _, address := range []string{"", "2001:4860::1", "::ffff:8.8.8.8"} {
		c := ipv6JSONFixture(t, false)
		c.Address = address
		if err := c.Validate(); err == nil {
			t.Errorf("accepted installation address %q", address)
		}
	}
	c := ipv6JSONFixture(t, false)
	c.IPv6 = true
	if err := c.Validate(); err == nil {
		t.Fatal("accepted legacy IPv6 together with ipv6_nodes")
	}
}

func TestIPv6JSONRejectsSelectedProtocolMissingFromConfig(t *testing.T) {
	c := ipv6JSONFixture(t, false)
	c.Protocols = c.Protocols[1:]
	if err := c.Validate(); err == nil {
		t.Fatal("accepted selected protocol absent from Config.Protocols")
	}
}

func TestIPv6JSONValidPublicAddressesAndLocalBindings(t *testing.T) {
	for _, address := range []string{"2001:4860:4860::8888", "2606:4700:4700::1111", "2a00:1450::1", "2001:200::1"} {
		c, err := New()
		if err != nil {
			t.Fatal(err)
		}
		c.Address = "10.0.0.2"
		c = withIPv6JSON(t, c, ipv6JSONSettings{true, address, []string{"anytls"}, []string{"10.0.0.2", "100.64.0.2", "127.0.0.1", "8.8.8.8"}})
		if err := c.Validate(); err != nil {
			t.Errorf("rejected public IPv6 %s or specific IPv4 bindings: %v", address, err)
		}
	}
}

func TestIPv6JSONNamesRejectPublishedCollisionsOnlyWhenOn(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	c.Protocols[0].Name = "custom"
	c.Protocols[1].Name = "custom · IPv6"
	if err := c.Validate(); err == nil {
		t.Fatal("accepted generated IPv6 name colliding with published IPv4 name")
	}
	c = withIPv6JSON(t, c, ipv6JSONSettings{false, "2001:4860:4860::8888", []string{"vless"}, []string{"10.0.0.2"}})
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled IPv6 changed legacy name validation: %v", err)
	}
}

func TestIPv6JSONRejectsOverlongGeneratedNameOnlyWhenOn(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	c.Protocols[0].Name = strings.Repeat("x", 250)
	if err := c.Validate(); err == nil {
		t.Fatal("accepted overlong generated IPv6 name")
	}
	c = withIPv6JSON(t, c, ipv6JSONSettings{false, "2001:4860:4860::8888", []string{"vless"}, []string{"10.0.0.2"}})
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled IPv6 changed legacy name length validation: %v", err)
	}
}

func TestIPv6CloneSeparatesSettingsAndBothSlices(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	before, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	clone := c.Clone()
	clone.IPv6Nodes.Enabled = false
	clone.IPv6Nodes.Address = "2606:4700:4700::1111"
	clone.IPv6Nodes.Protocols[0] = "anytls"
	clone.IPv6Nodes.IPv4ListenAddresses[0] = "192.168.0.2"
	after, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("mutating clone changed original IPv6 settings")
	}
	clone.IPv6Nodes = nil
	if clone.Clone().IPv6Nodes != nil {
		t.Fatal("cloning nil settings created an IPv6 configuration")
	}
}

func TestIPv6ProtocolSelectionIsIndependent(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	c.Protocols[0].Enabled = false
	if !c.HasIPv6Nodes() || !c.IPv6ProtocolEnabled("vless") || !c.IPv6ProtocolEnabled("tuic") {
		t.Fatal("IPv6 selection incorrectly depended on original Enabled flags")
	}
	for _, typ := range []string{"ss", "hysteria2", "anytls", "unknown", ""} {
		if c.IPv6ProtocolEnabled(typ) {
			t.Errorf("unselected protocol %q enabled", typ)
		}
	}
	c.IPv6Nodes.Enabled = false
	if c.HasIPv6Nodes() || c.IPv6ProtocolEnabled("vless") {
		t.Fatal("saved-but-disabled settings enabled IPv6 nodes")
	}
	c.IPv6Nodes = nil
	if c.HasIPv6Nodes() || c.IPv6ProtocolEnabled("vless") {
		t.Fatal("legacy configuration enabled IPv6 nodes")
	}
}

func TestIPv6NodeNamesPreserveOriginalDisplay(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	if got := c.IPv6NodeName(c.Protocols[0]); got != "NodeKit-vless · IPv6" {
		t.Fatal(got)
	}
	c.DisplayMode, c.CountryCode, c.Name = "flag-host", "JP", "osaka"
	if got := c.IPv6NodeName(c.Protocols[0]); got != "🇯🇵 osaka · VLESS · IPv6" {
		t.Fatal(got)
	}
	c.Protocols[0].Name = "custom"
	if got := c.IPv6NodeName(c.Protocols[0]); got != "custom · IPv6" {
		t.Fatal(got)
	}
	if got := c.NodeName(c.Protocols[0]); got != "custom" {
		t.Fatalf("IPv4 name changed: %q", got)
	}
}

func TestIPv6NamesIgnoreUnpublishedIPv4Collisions(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	c.Protocols[0].Name = "custom"
	c.Protocols[1].Name = "custom · IPv6"
	c.Protocols[1].Enabled = false
	if err := c.Validate(); err != nil {
		t.Fatalf("unpublished original name blocked IPv6 publication: %v", err)
	}
	c.Protocols[1].Name = "custom"
	if err := c.Validate(); err == nil {
		t.Fatal("IPv6 configuration bypassed legacy duplicate-original-name validation")
	}
}

func TestIPv6ListenerEndpointsPreserveLegacyBindings(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		c := ipv6JSONFixture(t, true)
		c.IPv6Nodes = nil
		c.IPv6 = ipv6
		for i := range c.Protocols {
			c.Protocols[i].Enabled = i == 0 || i == 2
		}
		address := "0.0.0.0"
		if ipv6 {
			address = "::"
		}
		want := []ListenerEndpoint{
			{Name: "nodekit-vless", Address: address, Family: "legacy", Protocol: c.Protocols[0]},
			{Name: "nodekit-tuic", Address: address, Family: "legacy", Protocol: c.Protocols[2]},
		}
		if got := c.ListenerEndpoints(); !reflect.DeepEqual(got, want) {
			t.Fatalf("legacy IPv6=%v endpoints = %+v, want %+v", ipv6, got, want)
		}
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "ipv6_nodes") {
			t.Fatal("nil ipv6_nodes was not omitted from legacy JSON")
		}
	}
}

func TestIPv6ListenerEndpointsUseProtocolOrderAndExplicitAddresses(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	c.IPv6Nodes.Protocols = []string{"ss", "vless"}
	c.IPv6Nodes.IPv4ListenAddresses = append(c.IPv6Nodes.IPv4ListenAddresses, "192.168.1.2")
	for i := range c.Protocols {
		c.Protocols[i].Enabled = i == 0 || i == 2
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	before := c.Clone()
	want := []ListenerEndpoint{
		{Name: "nodekit-vless", Address: "10.0.0.2", Family: "ipv4", Protocol: c.Protocols[0]},
		{Name: "nodekit-vless-ipv4-2", Address: "127.0.0.1", Family: "ipv4", Protocol: c.Protocols[0]},
		{Name: "nodekit-vless-ipv4-3", Address: "192.168.1.2", Family: "ipv4", Protocol: c.Protocols[0]},
		{Name: "nodekit-vless-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[0]},
		{Name: "nodekit-ss-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[1]},
		{Name: "nodekit-tuic", Address: "10.0.0.2", Family: "ipv4", Protocol: c.Protocols[2]},
		{Name: "nodekit-tuic-ipv4-2", Address: "127.0.0.1", Family: "ipv4", Protocol: c.Protocols[2]},
		{Name: "nodekit-tuic-ipv4-3", Address: "192.168.1.2", Family: "ipv4", Protocol: c.Protocols[2]},
	}
	got := c.ListenerEndpoints()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(c, before) {
		t.Fatal("enumerating listeners mutated original protocol settings")
	}
	got[0].Protocol.Password = "changed"
	if !reflect.DeepEqual(c, before) {
		t.Fatal("endpoint protocol aliases original settings")
	}
	c.IPv6Nodes.Enabled = false
	want = []ListenerEndpoint{want[0], want[1], want[2], want[5], want[6], want[7]}
	if got := c.ListenerEndpoints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("disabled IPv6 must retain specific IPv4 listeners: %+v", got)
	}
}

func TestIPv6ListenerEndpointsSupportAllIPv6OnlyProtocols(t *testing.T) {
	c := ipv6JSONFixture(t, true)
	c.IPv6Nodes.Protocols = []string{"anytls", "hysteria2", "tuic", "ss", "vless"}
	for i := range c.Protocols {
		c.Protocols[i].Enabled = false
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []ListenerEndpoint{
		{Name: "nodekit-vless-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[0]},
		{Name: "nodekit-ss-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[1]},
		{Name: "nodekit-tuic-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[2]},
		{Name: "nodekit-hysteria2-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[3]},
		{Name: "nodekit-anytls-ipv6", Address: "2001:4860:4860::8888", Family: "ipv6", Protocol: c.Protocols[4]},
	}
	if got := c.ListenerEndpoints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6-only endpoints = %+v, want %+v", got, want)
	}
	c.IPv6Nodes.Enabled = false
	if got := c.ListenerEndpoints(); len(got) != 0 {
		t.Fatalf("disabled protocols produced listeners: %+v", got)
	}
	c.IPv6Nodes = nil
	if got := c.ListenerEndpoints(); len(got) != 0 {
		t.Fatalf("disabled legacy protocols produced listeners: %+v", got)
	}
}

func TestIPv6DoesNotChangeDNSOrLegacyAddressSemantics(t *testing.T) {
	for _, mode := range []string{"direct", "cloudflare"} {
		c := ipv6JSONFixture(t, true)
		c.SubscriptionMode, c.SubscriptionPort = mode, 8443
		old := c.Clone()
		old.IPv6Nodes = nil
		if DNSFieldsChanged(old, c) {
			t.Fatal("IPv6-only change triggered DNS work")
		}
		want := "node.example.com"
		if mode == "cloudflare" {
			want = "8.8.8.8"
		}
		if got := c.NodeAddress(); got != want {
			t.Fatalf("%s NodeAddress = %q, want %q", mode, got, want)
		}
		before, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) || c.IPv6 {
			t.Fatal("pure model validation changed config or enabled legacy IPv6")
		}
	}
}
