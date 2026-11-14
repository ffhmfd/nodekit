package render

import (
	"nodekit/internal/model"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDDNSSubscriptionsPreserveHostnameAndTLS(t *testing.T) {
	for _, mode := range []string{"direct", "cloudflare"} {
		for _, provider := range []bool{false, true} {
			c, _ := model.New()
			c.Address, c.SubscriptionMode, c.SubscriptionPort = "DDNS.EXAMPLE.COM.", mode, 8443
			b, err := Subscription(c, provider)
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err = yaml.Unmarshal(b, &result); err != nil {
				t.Fatal(err)
			}
			nodes := result["proxies"].([]any)
			if len(nodes) != 5 {
				t.Fatal("missing protocols")
			}
			for _, raw := range nodes {
				n := raw.(map[string]any)
				if n["server"] != "ddns.example.com" || n["ip-version"] != "ipv4" {
					t.Fatalf("incorrect DDNS endpoint: %v", n)
				}
				switch n["type"] {
				case "vless":
					if n["servername"] != c.Reality.ServerName {
						t.Fatal("REALITY SNI changed")
					}
				case "ss":
				default:
					if n["sni"] != "node.example.com" || n["skip-cert-verify"] != false {
						t.Fatal("TLS identity changed")
					}
				}
			}
			if provider {
				if len(result) != 1 {
					t.Fatal("provider gained client settings")
				}
			} else {
				dns := result["dns"].(map[string]any)
				servers, ok := dns["proxy-server-nameserver"].([]any)
				if !ok || len(servers) == 0 {
					t.Fatal("no independent node DNS")
				}
			}
		}
	}
}
