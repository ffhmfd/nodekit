package cli

import (
	"errors"
	"nodekit/internal/model"
	"os"
	"sort"
)

func beginConfigRequirements(p paths, old, next model.Config) (func() error, func() error, error) {
	commitIPv6, abortIPv6, err := beginIPv6Requirement(p, old, next)
	if err != nil {
		return nil, nil, err
	}
	commitTraffic, abortTraffic, err := beginFeatureRequirement(p, "traffic-multiplier-v1", old.EffectiveTrafficMultiplier() == 2, next.EffectiveTrafficMultiplier() == 2)
	if err != nil {
		return nil, nil, errors.Join(err, abortIPv6())
	}
	return func() error { return errors.Join(commitIPv6(), commitTraffic()) },
		func() error { return errors.Join(abortIPv6(), abortTraffic()) }, nil
}

// Persist requirements before a candidate can reach the manager. Older recovery
// helpers honor RequiredFeatures even when they cannot decode a new Config field.
func beginFeatureRequirement(p paths, name string, oldRequired, nextRequired bool) (func() error, func() error, error) {
	noop := func() error { return nil }
	m, err := loadHost(p)
	if errors.Is(err, os.ErrNotExist) && !oldRequired && !nextRequired {
		return noop, noop, nil
	}
	if err != nil {
		return nil, nil, err
	}
	previouslyRequired := oldRequired
	for _, feature := range m.RequiredFeatures {
		if feature == name {
			previouslyRequired = true
		}
	}
	// Recovery can restore the old configuration after the process that wrote
	// this intent exits. Only a fresh successful transaction may remove it;
	// abort must preserve it even when both configurations are already disabled.
	if !previouslyRequired && !nextRequired {
		return noop, noop, nil
	}
	set := func(required bool) error {
		current, err := loadHost(p)
		if err != nil {
			return err
		}
		features := make([]string, 0, len(current.RequiredFeatures)+1)
		present := false
		for _, feature := range current.RequiredFeatures {
			if feature == name {
				present = true
				continue
			}
			features = append(features, feature)
		}
		if present == required {
			return nil
		}
		if required {
			features = append(features, name)
		}
		sort.Strings(features)
		current.RequiredFeatures = features
		return saveHost(p, current)
	}
	if err := set(previouslyRequired || nextRequired); err != nil {
		return nil, nil, err
	}
	return func() error { return set(nextRequired) }, func() error { return set(previouslyRequired) }, nil
}
