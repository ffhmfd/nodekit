package model

import (
	"errors"
	"net/netip"
)

func (c Config) EffectiveSubscriptionMode() string {
	if c.SubscriptionMode == "" {
		return "direct"
	}
	return c.SubscriptionMode
}

func (c Config) NodeAddress() string {
	if c.EffectiveSubscriptionMode() == "cloudflare" {
		if ip, err := netip.ParseAddr(c.Address); err == nil {
			return ip.Unmap().String()
		}
		return c.Address
	}
	return c.Domain
}

func CloudflareHTTPSPort(port int) bool {
	switch port {
	case 2053, 2083, 2087, 2096, 8443:
		return true
	}
	return false
}

// Exclude special-use ranges not covered by IsGlobalUnicast/IsPrivate.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// ValidateSubscription also serves issuance checks before credentials exist.
func (c Config) ValidateSubscription() error {
	switch c.EffectiveSubscriptionMode() {
	case "direct":
		return nil
	case "cloudflare":
	default:
		return errors.New("subscription mode must be direct or cloudflare")
	}
	if !CloudflareHTTPSPort(c.SubscriptionPort) {
		return errors.New("cloudflare HTTPS port must be 2053, 2083, 2087, 2096 or 8443")
	}
	ip, err := netip.ParseAddr(c.Address)
	if err != nil || ip.Zone() != "" {
		return errors.New("cloudflare nodes require a public unicast IP")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip)) {
		return errors.New("cloudflare nodes require a public unicast IP")
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return errors.New("cloudflare node address is reserved")
		}
	}
	if ip.Is6() && !c.IPv6 {
		return errors.New("IPv6 node address requires IPv6 enabled")
	}
	return nil
}

func (c *Config) SetSubscriptionMode(mode string) error {
	if mode != "direct" && mode != "cloudflare" {
		return errors.New("subscription mode must be direct or cloudflare")
	}
	next := c.Clone()
	next.SubscriptionMode = mode
	if mode == "cloudflare" && !CloudflareHTTPSPort(next.SubscriptionPort) {
		next.SubscriptionPort = 8443
	}
	if err := next.Validate(); err != nil {
		return err
	}
	*c = next
	return nil
}
