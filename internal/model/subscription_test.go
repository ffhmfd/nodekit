package model

import (
	"encoding/json"
	"testing"
)

func TestLegacySubscriptionRemainsDirect(t *testing.T) {
	c, _ := New()
	b, _ := json.Marshal(c)
	var legacy Config
	if e := json.Unmarshal(b, &legacy); e != nil {
		t.Fatal(e)
	}
	if legacy.EffectiveSubscriptionMode() != "direct" || legacy.NodeAddress() != c.Domain || legacy.SubscriptionPort != 24446 {
		t.Fatal("legacy behavior changed")
	}
}
func TestCloudflareValidation(t *testing.T) {
	for _, address := range []string{"1.1.1.1", "9.9.9.9", "8.8.8.8", "::ffff:8.8.8.8", "2001:4860:4860::8888"} {
		c, _ := New()
		c.Address = address
		c.IPv6 = true
		c.SubscriptionMode = "cloudflare"
		c.SubscriptionPort = 8443
		if e := c.Validate(); e != nil {
			t.Fatalf("valid public address %s: %v", address, e)
		}
	}
	for _, address := range []string{"", "localhost", "0.0.0.0", "0.1.2.3", "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "240.0.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "::", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:192.168.1.1", "2001:db8::1", "2002:7f00:1::", "3fff::1", "2001:4860::1%eth0"} {
		c, _ := New()
		c.Address = address
		c.IPv6 = true
		c.SubscriptionMode = "cloudflare"
		c.SubscriptionPort = 8443
		if c.Validate() == nil {
			t.Fatalf("accepted nonpublic address %s", address)
		}
	}
	c, _ := New()
	c.SubscriptionMode = "cloudflare"
	c.Address = "2001:4860:4860::8888"
	c.SubscriptionPort = 8443
	if c.Validate() == nil {
		t.Fatal("IPv6 address accepted without IPv6 enabled")
	}
}
func TestModeSwitchIsAtomicAndExplicit(t *testing.T) {
	c, _ := New()
	c.Address = "8.8.8.8"
	token := c.Token
	if e := c.SetSubscriptionMode("cloudflare"); e != nil {
		t.Fatal(e)
	}
	if c.SubscriptionPort != 8443 || c.NodeAddress() != "8.8.8.8" || c.Token != token {
		t.Fatal("bad mode switch")
	}
	c.SubscriptionPort = 2053
	if e := c.SetSubscriptionMode("direct"); e != nil || c.SubscriptionPort != 2053 || c.NodeAddress() != c.Domain {
		t.Fatal("direct switch", e)
	}
	if e := c.SetSubscriptionMode("bogus"); e == nil || c.EffectiveSubscriptionMode() != "direct" {
		t.Fatal("invalid mode mutated config")
	}
	c.SubscriptionPort = 24446
	c.Protocols[0].Port = 8443
	if e := c.SetSubscriptionMode("cloudflare"); e == nil || c.SubscriptionPort != 24446 || c.EffectiveSubscriptionMode() != "direct" {
		t.Fatal("conflicting mode switch was committed")
	}
}
func TestCloudflarePorts(t *testing.T) {
	for _, port := range []int{2053, 2083, 2087, 2096, 8443} {
		c, _ := New()
		c.Address = "8.8.8.8"
		c.SubscriptionMode = "cloudflare"
		c.SubscriptionPort = port
		if e := c.Validate(); e != nil {
			t.Fatal(port, e)
		}
	}
	for _, port := range []int{443, 80, 8080, 24446} {
		c, _ := New()
		c.Address = "8.8.8.8"
		c.SubscriptionMode = "cloudflare"
		c.SubscriptionPort = port
		if c.Validate() == nil {
			t.Fatal("unsupported port accepted", port)
		}
	}
}
