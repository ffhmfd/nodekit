package render

import (
	"nodekit/internal/model"
	"strings"
	"testing"
)

func TestIPv6SubscriptionPinsProxyAddressFamily(t *testing.T) {
	c, err := model.New()
	if err != nil {
		t.Fatal(err)
	}
	c.IPv6Nodes = &model.IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless"}, IPv4ListenAddresses: []string{"127.0.0.1"}}
	for _, provider := range []bool{false, true} {
		b, err := Subscription(c, provider)
		nodes := ipv6YAML(t, b, err)["proxies"].([]any)
		for _, raw := range nodes {
			node := raw.(obj)
			family := "ipv4"
			if strings.HasSuffix(node["name"].(string), " · IPv6") {
				family = "ipv6"
			} else if node["server"] != c.Domain {
				t.Fatal("original domain semantics changed")
			}
			if family == "ipv4" && node["ip-version"] != "ipv4" {
				t.Fatal("client may resolve an IPv4 node's domain via IPv6 after enabling dual-family subscriptions", node["name"], node["ip-version"])
			}
			if family == "ipv6" {
				if _, forced := node["ip-version"]; forced {
					t.Fatal("literal IPv6 server does not need a DNS constraint on target traffic")
				}
			}
		}
	}
	c.IPv6Nodes = nil
	b, err := Subscription(c, true)
	for _, raw := range ipv6YAML(t, b, err)["proxies"].([]any) {
		if _, exists := raw.(obj)["ip-version"]; exists {
			t.Fatal("unused feature changed legacy proxy output")
		}
	}
}
