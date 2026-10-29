package model

import (
	"errors"
	"fmt"
	"net/netip"
)

type IPv6NodesConfig struct {
	Enabled             bool     `json:"enabled"`
	Address             string   `json:"address"`
	Protocols           []string `json:"protocols"`
	IPv4ListenAddresses []string `json:"ipv4_listen_addresses"`
}

type ListenerEndpoint struct {
	Name     string
	Address  string
	Family   string
	Protocol Protocol
}

// HasIPv6Nodes reports whether the additional IPv6 nodes are enabled, not
// whether settings have been saved for them.
func (c Config) HasIPv6Nodes() bool {
	return c.IPv6Nodes != nil && c.IPv6Nodes.Enabled
}

// IPv6ProtocolEnabled is independent of the original Protocol.Enabled flag.
func (c Config) IPv6ProtocolEnabled(typ string) bool {
	if !c.HasIPv6Nodes() {
		return false
	}
	for _, selected := range c.IPv6Nodes.Protocols {
		if selected == typ {
			return true
		}
	}
	return false
}

// ListenerEndpoints enumerates validated configuration in protocol order, with
// each protocol's IPv4 bindings (in saved order) before its IPv6 binding.
// A saved-but-disabled IPv6 configuration still uses explicit IPv4 bindings.
func (c Config) ListenerEndpoints() []ListenerEndpoint {
	var endpoints []ListenerEndpoint
	for _, p := range c.Protocols {
		name := "nodekit-" + p.Type
		if c.IPv6Nodes == nil {
			if p.Enabled {
				address := "0.0.0.0"
				if c.IPv6 {
					address = "::"
				}
				endpoints = append(endpoints, ListenerEndpoint{Name: name, Address: address, Family: "legacy", Protocol: p})
			}
			continue
		}
		if p.Enabled {
			for i, address := range c.IPv6Nodes.IPv4ListenAddresses {
				bindingName := name
				if i > 0 {
					bindingName = fmt.Sprintf("%s-ipv4-%d", name, i+1)
				}
				endpoints = append(endpoints, ListenerEndpoint{Name: bindingName, Address: address, Family: "ipv4", Protocol: p})
			}
		}
		if c.IPv6ProtocolEnabled(p.Type) {
			endpoints = append(endpoints, ListenerEndpoint{Name: name + "-ipv6", Address: c.IPv6Nodes.Address, Family: "ipv6", Protocol: p})
		}
	}
	return endpoints
}

// validateIPv6Nodes only checks persisted model invariants. Addresses must
// already be canonical; discovering local addresses and probing sockets belong
// to the apply path, not model validation.
func (c Config) validateIPv6Nodes() error {
	if c.IPv6Nodes == nil {
		return nil
	}
	ipv4, err := netip.ParseAddr(c.Address)
	if err != nil || !ipv4.Is4() || c.IPv6 {
		return errors.New("IPv6 nodes require an IPv4 installation with legacy IPv6 disabled")
	}
	nodes := c.IPv6Nodes
	ipv6, err := netip.ParseAddr(nodes.Address)
	if err != nil || !ipv6.Is6() || ipv6.Is4In6() || ipv6.Zone() != "" || ipv6.String() != nodes.Address {
		return errors.New("IPv6 node address must be a canonical native IPv6 literal without a zone")
	}
	if !ipv6.IsGlobalUnicast() || ipv6.IsPrivate() || !netip.MustParsePrefix("2000::/3").Contains(ipv6) {
		return errors.New("IPv6 node address must be public unicast")
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ipv6) {
			return errors.New("IPv6 node address is reserved")
		}
	}
	if len(nodes.Protocols) == 0 {
		return errors.New("IPv6 nodes require at least one selected protocol")
	}
	available := map[string]bool{}
	for _, p := range c.Protocols {
		available[p.Type] = true
	}
	selected := map[string]bool{}
	for _, typ := range nodes.Protocols {
		switch typ {
		case "vless", "ss", "tuic", "hysteria2", "anytls":
		default:
			return errors.New("unknown IPv6 protocol")
		}
		if !available[typ] || selected[typ] {
			return errors.New("missing or duplicate IPv6 protocol")
		}
		selected[typ] = true
	}
	if len(nodes.IPv4ListenAddresses) == 0 {
		return errors.New("IPv6 nodes require explicit IPv4 listen addresses")
	}
	addresses := map[string]bool{}
	for _, address := range nodes.IPv4ListenAddresses {
		ip, err := netip.ParseAddr(address)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != address {
			return errors.New("IPv4 listen address must be a canonical, specified, non-multicast IPv4 literal")
		}
		if addresses[address] {
			return errors.New("duplicate IPv4 listen address")
		}
		addresses[address] = true
	}
	return nil
}
