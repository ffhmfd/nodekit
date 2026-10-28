package model

import (
	"encoding/json"
	"testing"
)

func TestDisplayDefaultsAndOverrides(t *testing.T) {
	c, _ := New()
	if err := c.SetDisplayDefaults("osaka", "jp"); err != nil {
		t.Fatal(err)
	}
	if got := c.NodeName(c.Protocols[0]); got != "🇯🇵 osaka · VLESS" {
		t.Fatal(got)
	}
	if got := c.NodeName(c.Protocols[1]); got != "🇯🇵 osaka · SS2022" {
		t.Fatal(got)
	}
	c.Protocols[0].Name = "自定义节点"
	c.Name = "renamed"
	if c.NodeName(c.Protocols[0]) != "自定义节点" {
		t.Fatal("override lost")
	}
	c.Protocols[0].Name = ""
	c.CountryCode = ""
	if c.NodeName(c.Protocols[0]) != "🌐 renamed · VLESS" {
		t.Fatal("auto fallback failed")
	}
	for _, bad := range []string{"节点选择", "自动选择", "故障切换", "bad\x1b[31m"} {
		c.Protocols[0].Name = bad
		if c.Validate() == nil {
			t.Fatal("accepted unsafe/reserved display", bad)
		}
	}
	c.Protocols[0].Name = "same"
	c.Protocols[1].Name = "same"
	if c.Validate() == nil {
		t.Fatal("duplicate names")
	}
}

func TestDisplayRejectsCoreBuiltinProxyNames(t *testing.T) {
	for _, name := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"} {
		c, _ := New()
		c.Protocols[0].Name = name
		if err := c.Validate(); err == nil {
			t.Errorf("accepted reserved core name %s", name)
		}
	}
}

func TestLegacyDisplayJSONPreservesNames(t *testing.T) {
	c, _ := New()
	c.Name = "legacy"
	data, _ := json.Marshal(c)
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)
	delete(raw, "display_mode")
	delete(raw, "country_code")
	data, _ = json.Marshal(raw)
	var old Config
	if err := json.Unmarshal(data, &old); err != nil {
		t.Fatal(err)
	}
	if got := old.NodeName(old.Protocols[0]); got != "legacy-vless" {
		t.Fatal(got)
	}
}

func TestRealityDefaultsAndAtomicChange(t *testing.T) {
	c, _ := New()
	if c.Reality.ServerName != "addons.mozilla.org" || c.Reality.Target != "addons.mozilla.org:443" {
		t.Fatal("wrong new defaults")
	}
	key := c.Reality.PrivateKey
	if err := c.SetRealityServerName("example.com"); err != nil {
		t.Fatal(err)
	}
	if c.Reality.Target != "example.com:443" || c.Reality.ServerName != "example.com" || c.Reality.PrivateKey != key {
		t.Fatal("identity/target update wrong")
	}
	old := c.Reality
	if c.SetRealityServerName("https://example.com") == nil || c.Reality != old {
		t.Fatal("invalid SNI changed state")
	}
	for _, target := range []string{"example.com:abc", "example.com:0", "example.com:65536", "bad host:443"} {
		c.Reality.Target = target
		if c.Validate() == nil {
			t.Fatal("invalid target accepted", target)
		}
	}
}
