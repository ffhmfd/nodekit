package platform

import (
	"context"
	"fmt"
	"strings"
)

// Preflight checks the backend and every required address family without
// changing rules. Apply still verifies writes: the host may change afterwards.
func (f Firewall) Preflight(ctx context.Context, bindings []Binding) error {
	return f.preflight(ctx, nil, bindings, false, false)
}

// PreflightRecovery accounts for rules the durable journal authorizes recovery
// to remove. It never treats a foreign equivalent as owned and never mutates.
func (f Firewall) PreflightRecovery(ctx context.Context, known, desired []Binding, restore bool) error {
	return f.preflight(ctx, known, desired, true, restore)
}

func (f Firewall) preflight(ctx context.Context, known, bindings []Binding, recovery, restore bool) error {
	if err := validateBindings(known, bindings); err != nil {
		return err
	}
	if f.Run == nil {
		f.Run = Exec
	}
	backend, err := f.backend(ctx)
	if err != nil {
		return err
	}
	if backend == "ufw" {
		rules, status, err := f.ufwState(ctx)
		if err != nil {
			return err
		}
		desired := ufwDesired(bindings, rules, restore, !recovery)
		// Model the exact owned removals before checking the target. Otherwise
		// staged family-tagged rules can appear foreign to an old legacy target.
		removed := map[ufwRule]bool{}
		for rule := range ufwDefinitions(known) {
			if _, keep := desired[rule]; rules[rule] && !keep {
				removed[rule] = true
				delete(rules, rule)
			}
		}
		var remaining []string
		for _, line := range strings.Split(status, "\n") {
			owned := false
			for rule := range removed {
				if ufwPhysical(line, rule, "ipv4") || ufwPhysical(line, rule, "ipv6") {
					owned = true
					break
				}
			}
			if !owned {
				remaining = append(remaining, line)
			}
		}
		status = strings.Join(remaining, "\n")
		for rule, families := range desired {
			if ufwStoredRule(rules, rule) {
				for family := range families {
					if !ufwPhysical(status, rule, family) {
						return fmt.Errorf("stored UFW %s %s/%d allowance is not active", family, rule.network, rule.port)
					}
				}
				continue
			}
			for family := range families {
				if ufwEquivalent(status, rule, family) {
					return fmt.Errorf("UFW %s %s/%d conflicts with an existing rule", family, rule.network, rule.port)
				}
			}
		}
		// An active UFW can still have IPv6 disabled. Inspect its backend,
		// rather than adding a test rule (or accepting a skipped v6 write).
		for _, b := range expandBindings(append(append([]Binding(nil), known...), bindings...)) {
			if b.Family == "ipv6" {
				out, err := f.Run(ctx, "ufw", "--dry-run", "allow", "proto", b.Network, "from", "any", "to", "::/0", "port", fmt.Sprint(b.Port))
				if err != nil {
					return err
				}
				if !strings.Contains(string(out), "*filter") || !strings.Contains(string(out), "COMMIT") {
					return fmt.Errorf("UFW IPv6 support is disabled or unavailable")
				}
				break
			}
		}
		return nil
	}
	seen := map[string]bool{}
	for _, rule := range tableCandidates(append(append([]Binding(nil), known...), bindings...)) {
		if !seen[rule.tool] {
			if _, err := f.Run(ctx, rule.tool, "-S", "INPUT"); err != nil {
				return fmt.Errorf("%s INPUT unavailable: %w", rule.tool, err)
			}
			seen[rule.tool] = true
		}
		if _, err := f.tablePresent(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}
