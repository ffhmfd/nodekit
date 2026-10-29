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
	return reconcileFirewallWith(ctx, p, m, c, platform.Firewall{})
}

func reconcileFirewallWith(ctx context.Context, p paths, m hostManifest, c model.Config, f platform.Firewall) (hostManifest, error) {
	known := m.Firewall
	if m.PendingFirewall != nil {
		known = bindingsUnion(known, bindingsUnion(m.PendingFirewall.Old, m.PendingFirewall.New))
	}
	desired := platform.Bindings(c)
	// A pending transaction already captured Old before staging. Its mixed
	// Old/New inventory is cleanup authority, not a new physical observation
	// of Old. In particular, fresh init New may not have been installed yet.
	snapshot := append([]platform.Binding(nil), known...)
	var e error
	if m.PendingFirewall == nil {
		snapshot, e = f.Snapshot(ctx, m.Firewall)
		if e != nil {
			return m, e
		}
	}
	latest, e := loadHost(p)
	if e != nil {
		return m, e
	}
	if latest.PendingFirewall == nil {
		latest.PendingFirewall = &firewallOperation{Old: snapshot, New: desired, Revision: c.Revision}
	} else {
		// Snapshot retains its raw inputs, including staged New intent. It is
		// only a cleanup inventory here, never evidence of what belonged to
		// Old. Old's physical provenance was captured before the first mutation
		// and must remain immutable once the transaction has begun.
		latest.PendingFirewall.New = bindingsUnion(latest.PendingFirewall.New, desired)
	}
	if e = saveHost(p, latest); e != nil {
		return m, e
	}
	target := desired
	if latest.PendingFirewall.Revision == c.Revision {
		target = firewallRecoveryTarget(latest.PendingFirewall.Old, desired)
		e = f.Restore(ctx, snapshot, target)
	} else {
		e = f.Reconcile(ctx, snapshot, target)
	}
	if e != nil {
		return m, e
	}
	if e := finishFirewallChange(p, target); e != nil {
		return m, e
	}
	return loadHost(p)
}

// If the authoritative config is still at the journal's old revision, keep
// matching legacy physical provenance instead of reconstructing it from that
// config's logical IPv6 flag. Brand-new legacy intent (init) has no old generic
// ownership and is explicitly qualified, including during recovery.
func firewallRecoveryTarget(old, desired []platform.Binding) []platform.Binding {
	target := append([]platform.Binding(nil), desired...)
	for _, b := range desired {
		if b.Family != "" {
			continue
		}
		var physical []platform.Binding
		legacy := false
		for _, previous := range old {
			if previous.Network == b.Network && previous.Port == b.Port {
				physical = append(physical, previous)
				if previous.Family == "" {
					legacy = true
				}
			}
		}
		if legacy {
			target = bindingsUnion(target, physical)
		} else {
			target = bindingsUnion(target, platform.CoverageDifference([]platform.Binding{b}, nil))
		}
	}
	return target
}
func beginFirewallChange(ctx context.Context, p paths, old, next model.Config) (func() error, func() error, error) {
	m, e := loadHost(p)
	if e != nil {
		return nil, nil, e
	}
	if e = verifyAccount(p, m); e != nil {
		return nil, nil, e
	}
	return beginFirewallChangeWith(ctx, p, old, next, platform.Firewall{})
}

func beginFirewallChangeWith(ctx context.Context, p paths, old, next model.Config, f platform.Firewall) (func() error, func() error, error) {
	m, e := loadHost(p)
	if e != nil {
		return nil, nil, e
	}
	if m.PendingFirewall != nil {
		m, e = reconcileFirewallWith(ctx, p, m, old, f)
		if e != nil {
			return nil, nil, e
		}
	}
	// Ownership comes from the manifest, not reconstructed old configuration.
	// Snapshot retains legacy generic UFW physical provenance as well as the
	// original raw binding. Logical family subtraction is not a deletion plan.
	before, e := f.Snapshot(ctx, m.Firewall)
	if e != nil {
		return nil, nil, e
	}
	after := platform.Bindings(next)
	m.PendingFirewall = &firewallOperation{Old: before, New: after, Revision: old.Revision}
	if e = saveHost(p, m); e != nil {
		return nil, nil, e
	}
	known := bindingsUnion(before, after)
	abort := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := f.Restore(cleanup, known, before); e != nil {
			return e
		}
		return finishFirewallChange(p, before)
	}
	if e = f.Reconcile(ctx, before, after); e != nil {
		return nil, nil, errors.Join(e, abort())
	}
	commit := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := f.Reconcile(cleanup, known, after); e != nil {
			return e
		}
		return finishFirewallChange(p, after)
	}
	return commit, abort, nil
}

// During a root-coordinated change the operation lock is already held. A
// systemd apply hook must only ensure the staged target, never replay the raw
// ownership union (which can resurrect a migrated generic UFW rule).
func firewallApplyBindings(m hostManifest) []platform.Binding {
	if m.PendingFirewall != nil {
		return m.PendingFirewall.New
	}
	return m.Firewall
}

// Init/resume record intent without losing old physical provenance or an
// interrupted transaction. The privileged firewall apply hook resolves the
// journal against the authoritative service config under the operation lock.
func rememberFirewallIntent(m *hostManifest, c model.Config) {
	desired := platform.Bindings(c)
	if m.PendingFirewall == nil && (len(difference(m.Firewall, desired)) != 0 || len(difference(desired, m.Firewall)) != 0) {
		m.PendingFirewall = &firewallOperation{Old: append([]platform.Binding(nil), m.Firewall...), New: desired, Revision: c.Revision}
	}
	m.Firewall = bindingsUnion(m.Firewall, desired)
}
