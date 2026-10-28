package cli

import (
	"context"
	"errors"
	"nodekit/internal/model"
	"nodekit/internal/platform"
	"time"
)

// DNS coordination may have committed a newer ownership manifest while the
// firewall transaction was open. Only replace the fields owned by this step.
func finishFirewallChange(p paths, bindings []platform.Binding) error {
	m, err := loadHost(p)
	if err != nil {
		return err
	}
	m.Firewall = bindings
	m.PendingFirewall = nil
	return saveHost(p, m)
}

func reconcileFirewall(ctx context.Context, p paths, m hostManifest, c model.Config) (hostManifest, error) {
	f := platform.Firewall{}
	known := m.Firewall
	if m.PendingFirewall != nil {
		known = bindingsUnion(known, bindingsUnion(m.PendingFirewall.Old, m.PendingFirewall.New))
	}
	desired := platform.Bindings(c)
	if e := f.Apply(ctx, desired); e != nil {
		return m, e
	}
	if e := f.Remove(ctx, difference(known, desired)); e != nil {
		return m, e
	}
	m.Firewall = desired
	m.PendingFirewall = nil
	return m, saveHost(p, m)
}
func beginFirewallChange(ctx context.Context, p paths, old, next model.Config) (func() error, func() error, error) {
	m, e := loadHost(p)
	if e != nil {
		return nil, nil, e
	}
	if e = verifyAccount(p, m); e != nil {
		return nil, nil, e
	}
	if m.PendingFirewall != nil {
		m, e = reconcileFirewall(ctx, p, m, old)
		if e != nil {
			return nil, nil, e
		}
	}
	before, after := platform.Bindings(old), platform.Bindings(next)
	added, removed := difference(after, before), difference(before, after)
	if len(added) == 0 && len(removed) == 0 {
		return func() error { return nil }, func() error { return nil }, nil
	}
	m.PendingFirewall = &firewallOperation{Old: before, New: after, Revision: old.Revision}
	if e = saveHost(p, m); e != nil {
		return nil, nil, e
	}
	f := platform.Firewall{}
	abort := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := f.Remove(cleanup, added); e != nil {
			return e
		}
		return finishFirewallChange(p, before)
	}
	if e = f.Apply(ctx, added); e != nil {
		return nil, nil, errors.Join(e, abort())
	}
	commit := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := f.Remove(cleanup, removed); e != nil {
			return e
		}
		return finishFirewallChange(p, after)
	}
	return commit, abort, nil
}
