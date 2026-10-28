package render

import (
	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
	"testing"
)

func TestCloudflareNodesKeepTLSIdentity(t *testing.T) {
	c, _ := model.New()
	c.Address = "::ffff:8.8.8.8"
	c.SubscriptionMode = "cloudflare"
	c.SubscriptionPort = 8443
	for _, provider := range []bool{false, true} {
		b, e := Subscription(c, provider)
		if e != nil {
			t.Fatal(e)
		}
		var result map[string]any
		if e = yaml.Unmarshal(b, &result); e != nil {
			t.Fatal(e)
		}
		nodes := result["proxies"].([]any)
		if len(nodes) != 5 {
			t.Fatal("missing protocol")
		}
		for _, raw := range nodes {
			n := raw.(map[string]any)
			if n["server"] != "8.8.8.8" {
				t.Fatal("node still dials domain or noncanonical address", n["type"], n["server"])
			}
			switch n["type"] {
			case "vless":
				if n["servername"] != c.Reality.ServerName || n["reality-opts"].(map[string]any)["public-key"] != c.Reality.PublicKey {
					t.Fatal("REALITY identity changed")
				}
			case "ss":
				if _, ok := n["sni"]; ok {
					t.Fatal("SS gained TLS")
				}
			default:
				if n["sni"] != c.Domain || n["skip-cert-verify"] != false {
					t.Fatal("TLS identity weakened")
				}
			}
		}
	}
}
