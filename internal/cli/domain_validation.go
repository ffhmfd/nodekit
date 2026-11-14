package cli

import (
	"context"
	"errors"
	"net"
	"nodekit/internal/model"
)

func validateDomainAddress(ctx context.Context, mode, domain, address string, lookup func(context.Context, string) ([]net.IPAddr, error)) error {
	if !model.ValidDomain(domain) {
		return errors.New("invalid certificate domain")
	}
	c := model.Config{SubscriptionMode: mode, Domain: domain, Address: address, IPv6: true, SubscriptionPort: 8443}
	if err := c.ValidateSubscription(); err != nil {
		return err
	}
	if c.EffectiveSubscriptionMode() == "cloudflare" {
		return nil
	}
	var configured []net.IPAddr
	if model.IsDomainAddress(address) {
		var err error
		configured, err = lookup(ctx, model.NormalizeAddress(address))
		if err != nil {
			return err
		}
	} else if ip := net.ParseIP(address); ip != nil {
		configured = []net.IPAddr{{IP: ip}}
	} else {
		return errors.New("address must be an IP or a DDNS domain")
	}
	ips, err := lookup(ctx, domain)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		for _, origin := range configured {
			if ip.IP.Equal(origin.IP) {
				return nil
			}
		}
	}
	return errors.New("订阅域名与配置 address 的当前解析不匹配；请检查灰云 A/AAAA/CNAME")
}
