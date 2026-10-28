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
	c := model.Config{SubscriptionMode: mode, Address: address, IPv6: true, SubscriptionPort: 8443}
	if err := c.ValidateSubscription(); err != nil {
		return err
	}
	if c.EffectiveSubscriptionMode() == "cloudflare" {
		return nil
	}
	configured := net.ParseIP(address)
	if configured == nil {
		return errors.New("address must be an IP")
	}
	ips, err := lookup(ctx, domain)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IP.Equal(configured) {
			return nil
		}
	}
	return errors.New("域名 A/AAAA 与配置 address 不匹配；请检查灰云解析")
}
