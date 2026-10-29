package render

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
)

func ipv6Config(t *testing.T) model.Config {
	t.Helper()
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.Address = "8.8.8.8"
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless", "ss", "tuic", "hysteria2", "anytls"}, IPv4ListenAddresses: []string{"127.0.0.1", "127.0.0.2"}}
	return c
}

func ipv6YAML(t *testing.T, b []byte, err error) obj {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var out obj
	if err = yaml.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIPv6ServerExplicitBindingsShareProtocolSettings(t *testing.T) {
	c := ipv6Config(t)
	paths := Paths{Socket: "/tmp/test.sock", Certificate: "/tmp/cert.pem", PrivateKey: "/tmp/key.pem"}
	legacy := c.Clone()
	legacy.IPv6Nodes = nil
	b, err := Server(legacy, paths)
	before := ipv6YAML(t, b, err)["listeners"].([]any)
	b, err = Server(c, paths)
	after := ipv6YAML(t, b, err)
	if after["ipv6"] != false {
		t.Fatal("additional listeners changed the server resolver flag")
	}
	listeners := after["listeners"].([]any)
	if len(listeners) != 15 {
		t.Fatalf("want 15 explicit listeners, got %d", len(listeners))
	}
	for i, p := range c.Protocols {
		for j, address := range []string{"127.0.0.1", "127.0.0.2", "2001:4860:4860::8888"} {
			l := listeners[i*3+j].(obj)
			name := "nodekit-" + p.Type + []string{"", "-ipv4-2", "-ipv6"}[j]
			if l["name"] != name || l["listen"] != address || l["port"] != p.Port {
				t.Fatalf("wrong endpoint: %v", l)
			}
			settings := obj{}
			for key, value := range l {
				settings[key] = value
			}
			settings["name"] = "nodekit-" + p.Type
			settings["listen"] = "0.0.0.0"
			if !reflect.DeepEqual(settings, before[i]) {
				t.Fatalf("%s changed shared protocol/TLS settings", name)
			}
		}
	}
}

func TestIPv6ServerIndependentSelectionAndSavedOffBindings(t *testing.T) {
	c := ipv6Config(t)
	c.IPv6Nodes.IPv4ListenAddresses = []string{"127.0.0.1"}
	c.IPv6Nodes.Protocols = []string{"ss", "tuic"}
	for i := range c.Protocols {
		c.Protocols[i].Enabled = c.Protocols[i].Type == "vless"
	}
	for _, enabled := range []bool{true, false} {
		c.IPv6Nodes.Enabled = enabled
		b, err := Server(c, Paths{})
		listeners := ipv6YAML(t, b, err)["listeners"].([]any)
		want := []string{"nodekit-vless"}
		if enabled {
			want = append(want, "nodekit-ss-ipv6", "nodekit-tuic-ipv6")
		}
		var names []string
		for _, raw := range listeners {
			l := raw.(obj)
			names = append(names, l["name"].(string))
			if l["listen"] == "0.0.0.0" || l["listen"] == "::" {
				t.Fatal("saved feature settings must never restore wildcard listeners")
			}
		}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("enabled=%t: got %v, want %v", enabled, names, want)
		}
	}
}

func TestIPv6SubscriptionsAppendUnchangedCredentialsAndGroups(t *testing.T) {
	c := ipv6Config(t)
	c.Protocols[1].Name = "My SS"
	legacy := c.Clone()
	legacy.IPv6Nodes = nil
	b, err := Subscription(legacy, true)
	originals := ipv6YAML(t, b, err)["proxies"].([]any)
	for _, provider := range []bool{false, true} {
		b, err = Subscription(c, provider)
		out := ipv6YAML(t, b, err)
		nodes := out["proxies"].([]any)
		if len(nodes) != 10 {
			t.Fatalf("provider=%t: want 10 nodes, got %d", provider, len(nodes))
		}
		var names []string
		for i, raw := range nodes {
			n := raw.(obj)
			names = append(names, n["name"].(string))
			if i < 5 {
				expected := obj{}
				for key, value := range originals[i].(obj) {
					expected[key] = value
				}
				expected["ip-version"] = "ipv4"
				if !reflect.DeepEqual(n, expected) {
					t.Fatal("original node changed")
				}
				continue
			}
			base := originals[i-5].(obj)
			if _, constrained := n["ip-version"]; constrained {
				t.Fatal("literal IPv6 nodes must not force target DNS policy")
			}
			if n["name"] != base["name"].(string)+" · IPv6" || n["server"] != "2001:4860:4860::8888" {
				t.Fatalf("wrong appended IPv6 identity: %v", n)
			}
			copy := obj{}
			for k, v := range n {
				copy[k] = v
			}
			copy["name"], copy["server"] = base["name"], base["server"]
			delete(copy, "ip-version")
			if !reflect.DeepEqual(copy, base) {
				t.Fatalf("IPv6 node changed credentials, REALITY, SNI, fingerprint or TLS: %v", n)
			}
		}
		if provider {
			if len(out) != 1 {
				t.Fatal("provider overrides client settings")
			}
		} else {
			if out["ipv6"] != true || out["dns"].(obj)["ipv6"] != true {
				t.Fatal("IPv6 client support/DNS not enabled")
			}
			groups := routingGroups(t, out)
			for _, name := range []string{"节点选择", "自动选择", "故障切换"} {
				got := routingChoices(t, groups, name)
				want := names
				if name == "节点选择" {
					want = append(append([]string{"自动选择", "故障切换"}, names...), "DIRECT")
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("group %q omitted published nodes: got %v, want %v", name, got, want)
				}
			}
			assertRoutingGraph(t, out, "🤖 ChatGPT")
		}
		if strings.Contains(string(b), c.Token) || strings.Contains(string(b), c.Reality.PrivateKey) || strings.Contains(string(b), "skip-cert-verify: true") {
			t.Fatal("subscription leaked secrets or disabled TLS validation")
		}
	}
}

func TestIPv6SubscriptionSelectionIsIndependentAndOffOnlyRemovesIPv6(t *testing.T) {
	c := ipv6Config(t)
	c.IPv6Nodes.Protocols = []string{"ss", "tuic"}
	for i := range c.Protocols {
		c.Protocols[i].Enabled = c.Protocols[i].Type == "vless"
	}
	for _, enabled := range []bool{true, false} {
		c.IPv6Nodes.Enabled = enabled
		for _, provider := range []bool{true, false} {
			b, err := Subscription(c, provider)
			out := ipv6YAML(t, b, err)
			var got []string
			for _, raw := range out["proxies"].([]any) {
				got = append(got, raw.(obj)["name"].(string))
			}
			want := []string{"NodeKit-vless"}
			if enabled {
				want = append(want, "NodeKit-ss · IPv6", "NodeKit-tuic · IPv6")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("enabled=%t provider=%t: got %v, want %v", enabled, provider, got, want)
			}
			if !provider && (out["ipv6"] != enabled || out["dns"].(obj)["ipv6"] != enabled) {
				t.Fatal("client IPv6 flags do not follow enabled feature")
			}
		}
	}
}
