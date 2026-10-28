package render

import (
	"gopkg.in/yaml.v3"
	"nodekit/internal/model"
	"strings"
	"testing"
)

func TestServerAndSubscriptions(t *testing.T) {
	c, _ := model.New()
	server, e := Server(c, Paths{Socket: "/tmp/core.sock", Certificate: "/tmp/cert.pem", PrivateKey: "/tmp/key.pem"})
	if e != nil {
		t.Fatal(e)
	}
	var s map[string]any
	if e = yaml.Unmarshal(server, &s); e != nil {
		t.Fatal(e)
	}
	if len(s["listeners"].([]any)) != 5 || s["external-controller-unix"] != "/tmp/core.sock" {
		t.Fatal("wrong listeners/controller")
	}
	if s["rules"].([]any)[0] != "MATCH,DIRECT" {
		t.Fatal("server must route directly")
	}
	for _, provider := range []bool{false, true} {
		b, e := Subscription(c, provider)
		if e != nil {
			t.Fatal(e)
		}
		var m map[string]any
		if e = yaml.Unmarshal(b, &m); e != nil {
			t.Fatal(e)
		}
		if len(m["proxies"].([]any)) != 5 {
			t.Fatal("missing protocols")
		}
		if strings.Contains(string(b), c.Reality.PrivateKey) || strings.Contains(string(b), c.Token) {
			t.Fatal("private data leaked")
		}
		if strings.Contains(string(b), "skip-cert-verify: true") {
			t.Fatal("TLS validation disabled")
		}
		if provider && len(m) != 1 {
			t.Fatal("provider overrides user config")
		}
	}
	c.Protocols[0].Enabled = false
	b, _ := Subscription(c, true)
	var p map[string]any
	_ = yaml.Unmarshal(b, &p)
	if len(p["proxies"].([]any)) != 4 {
		t.Fatal("disabled node exported")
	}
}
