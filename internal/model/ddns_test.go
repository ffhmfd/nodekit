package model

import "testing"

func TestDDNSAddressValidation(t *testing.T) {
	for _, mode := range []string{"direct", "cloudflare"} {
		for _, address := range []string{"ddns.example.com", "DDNS.EXAMPLE.COM.", "xn--bcher-kva.example"} {
			c, _ := New()
			c.SubscriptionMode, c.SubscriptionPort, c.Address = mode, 8443, address
			if err := c.Validate(); err != nil {
				t.Errorf("%s / %s: %v", mode, address, err)
			}
		}
		for _, address := range []string{"https://ddns.example.com", "ddns.example.com:443", "ddns.example.com/path", "localhost", "-bad.example.com", "ddns..example.com", " ddns.example.com", "256.1.1.1", "1.2.3", "1.2.3.04", "123.456", "2001:db8::xyz", "NODE.EXAMPLE.COM."} {
			c, _ := New()
			c.SubscriptionMode, c.SubscriptionPort, c.Address = mode, 8443, address
			if err := c.Validate(); err == nil {
				t.Errorf("accepted invalid/self-referential address %q in %s", address, mode)
			}
		}
	}
}

func TestDDNSWithAdditionalIPv6Nodes(t *testing.T) {
	c, _ := New()
	c.Address = "ddns.example.com"
	c.IPv6Nodes = &IPv6NodesConfig{Enabled: true, Address: "2001:4860:4860::8888", Protocols: []string{"vless"}, IPv4ListenAddresses: []string{"10.0.0.2"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.ListenerEndpoints()[0].Address; got != "10.0.0.2" {
		t.Fatalf("DDNS used as a local bind: %s", got)
	}
}
