package render

import (
	"reflect"
	"testing"

	"nodekit/internal/model"
)

func TestClientNetworkReferenceSettings(t *testing.T) {
	doc := routingDocument(t, routingConfig(t), false)
	t.Run("DNS", func(t *testing.T) {
		dns, ok := doc["dns"].(obj)
		if !ok {
			t.Fatal("full subscription is missing DNS settings")
		}
		for key, want := range map[string]any{
			"enable": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16", "use-hosts": true,
		} {
			if got := dns[key]; got != want {
				t.Errorf("DNS %s: got %v, want %v", key, got, want)
			}
		}
		for _, tc := range []struct {
			key  string
			want []string
		}{
			{"fake-ip-filter", []string{"*", "+.lan", "+.local"}},
			{"default-nameserver", []string{"223.5.5.5", "1.12.12.12"}},
			{"nameserver", []string{"tls://223.5.5.5:853", "tls://1.12.12.12:853"}},
		} {
			t.Run(tc.key, func(t *testing.T) {
				if got := routingStrings(t, dns[tc.key]); !reflect.DeepEqual(got, tc.want) {
					t.Errorf("DNS %s: got %q, want %q", tc.key, got, tc.want)
				}
			})
		}
	})
	t.Run("sniffer", func(t *testing.T) {
		sniffer, ok := doc["sniffer"].(obj)
		if !ok {
			t.Fatal("full subscription is missing sniffer settings")
		}
		for _, key := range []string{"enable", "override-destination", "force-dns-mapping", "parse-pure-ip"} {
			if sniffer[key] != true {
				t.Errorf("sniffer %s must be enabled, got %v", key, sniffer[key])
			}
		}
		sniff, ok := sniffer["sniff"].(obj)
		if !ok {
			t.Fatal("missing sniffer protocol settings")
		}
		for _, tc := range []struct {
			protocol string
			ports    []any
		}{
			{"HTTP", []any{80, "8080-8880"}},
			{"TLS", []any{443, 8443}},
			{"QUIC", []any{443, 8443}},
		} {
			t.Run(tc.protocol, func(t *testing.T) {
				settings, ok := sniff[tc.protocol].(obj)
				if !ok {
					t.Fatalf("missing %s sniffer settings", tc.protocol)
				}
				if !reflect.DeepEqual(settings["ports"], tc.ports) || settings["override-destination"] != true {
					t.Errorf("wrong %s ports/destination override: %v", tc.protocol, settings)
				}
			})
		}
	})
}

func TestClientNetworkIPv6AndProviderIsolation(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		legacy, saved, enabled bool
		originalsOff, wantIPv6 bool
		wantNodes              int
	}{
		{"IPv4", false, false, false, false, false, 5},
		{"legacy_IPv6", true, false, false, false, true, 5},
		{"saved_IPv6_disabled", false, true, false, false, false, 5},
		{"additional_IPv6", false, true, true, false, true, 7},
		{"IPv6_only", false, true, true, true, true, 2},
		{"all_nodes_disabled", false, true, false, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := routingConfig(t)
			c.IPv6 = tc.legacy
			if tc.legacy {
				c.Address = "2001:4860:4860::8888"
			}
			if tc.saved {
				c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: tc.enabled, Address: "2001:4860:4860::8888", Protocols: []string{"ss", "tuic"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
			}
			if tc.originalsOff {
				for i := range c.Protocols {
					c.Protocols[i].Enabled = false
				}
			}
			before := c.Clone()
			full := routingDocument(t, c, false)
			provider := routingDocument(t, c, true)
			dns, ok := full["dns"].(obj)
			if !ok {
				t.Fatal("full subscription is missing DNS settings")
			}
			if full["ipv6"] != tc.wantIPv6 || dns["ipv6"] != tc.wantIPv6 {
				t.Errorf("client/DNS IPv6 must follow legacy or active additional nodes: client=%v DNS=%v want=%t", full["ipv6"], dns["ipv6"], tc.wantIPv6)
			}
			if len(provider) != 1 || !reflect.DeepEqual(provider["proxies"], full["proxies"]) {
				t.Error("provider must contain only unchanged proxies, without client settings")
			}
			nodes := full["proxies"].([]any)
			if len(nodes) != tc.wantNodes {
				t.Fatalf("got %d nodes, want %d", len(nodes), tc.wantNodes)
			}
			if tc.saved && !tc.originalsOff {
				for _, raw := range nodes[:5] {
					node := raw.(obj)
					if node["ip-version"] != "ipv4" {
						t.Errorf("original IPv4 node %v lost its address-family constraint", node["name"])
					}
				}
			}
			for _, key := range []string{"allow-lan", "bind-address", "external-controller", "external-controller-unix", "mixed-port", "port", "socks-port", "redir-port", "tproxy-port", "listeners", "tun"} {
				if _, exists := full[key]; exists {
					t.Errorf("client subscription must not introduce %s", key)
				}
			}
			if _, exists := dns["listen"]; exists {
				t.Error("DNS must not introduce a listener")
			}
			if !reflect.DeepEqual(c, before) {
				t.Error("subscription rendering mutated the configuration")
			}
		})
	}
}
