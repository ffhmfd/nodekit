package cli

import (
	"context"
	"nodekit/internal/model"
	"nodekit/internal/platform"
)

// Startup hooks run as children while the root parent holds operation.lock.
// Reconcile any older intent under that parent lock before a locked hook is
// allowed to ensure Pending.New. The config is inspected as the service UID.
func prepareFirewallStart(ctx context.Context, p paths) (hostManifest, error) {
	return prepareFirewallStartWith(ctx, p, platform.Firewall{}, serviceConfig)
}

func prepareFirewallStartWith(ctx context.Context, p paths, f platform.Firewall, inspect func(context.Context, paths) (model.Config, error)) (hostManifest, error) {
	m, err := loadHost(p)
	if err != nil || m.PendingFirewall == nil {
		return m, err
	}
	rt, err := p.runtime()
	if err != nil {
		return m, err
	}
	if rt.Firewall == "manual" {
		return m, nil
	}
	c, err := inspect(ctx, p)
	if err != nil {
		return m, err
	}
	return reconcileFirewallWith(ctx, p, m, c, f)
}
