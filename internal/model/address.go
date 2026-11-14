package model

import (
	"errors"
	"net/netip"
	"strings"
)

// NormalizeAddress canonicalizes an endpoint without resolving or pinning DNS.
func NormalizeAddress(address string) string {
	if ip, err := netip.ParseAddr(address); err == nil && ip.Zone() == "" {
		return ip.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(address, "."))
}

// IsDomainAddress excludes numeric-looking invalid IPs and URL/host:port input.
// Internationalized names must already use their ASCII (punycode) form.
func IsDomainAddress(address string) bool {
	if _, err := netip.ParseAddr(address); err == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(address, "."))
	if !ValidDomain(name) {
		return false
	}
	tld := name[strings.LastIndexByte(name, '.')+1:]
	return strings.ContainsAny(tld, "abcdefghijklmnopqrstuvwxyz")
}

// DNSRecord describes the subscription origin. A hostname remains a CNAME
// target; resolving it here would turn a DDNS configuration into a fixed IP.
func (c Config) DNSRecord() (kind, content string, err error) {
	if IsDomainAddress(c.Address) {
		content = NormalizeAddress(c.Address)
		if content == strings.ToLower(strings.TrimSuffix(c.Domain, ".")) {
			return "", "", errors.New("DDNS address must differ from subscription domain (CNAME loop)")
		}
		return "CNAME", content, nil
	}
	ip, err := netip.ParseAddr(c.Address)
	if err != nil || ip.Zone() != "" {
		return "", "", errors.New("address must be an IP or a DDNS domain without scheme, path or port")
	}
	ip = ip.Unmap()
	kind = "A"
	if ip.Is6() {
		kind = "AAAA"
	}
	return kind, ip.String(), nil
}
