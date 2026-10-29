package cli

import (
	"nodekit/internal/model"
	"sort"
)

// Persist the capability before changing listeners/rules. Older root helpers
// already honor arbitrary RequiredFeatures strings, even if they do not know
// how to decode the new Config field or an interrupted candidate.
func beginIPv6Requirement(p paths, old, next model.Config) (func() error, func() error, error) {
	noop := func() error { return nil }
	if old.IPv6Nodes == nil && next.IPv6Nodes == nil {
		return noop, noop, nil
	}
	m, err := loadHost(p)
	if err != nil {
		return nil, nil, err
	}
	previouslyRequired := old.IPv6Nodes != nil
	for _, feature := range m.RequiredFeatures {
		if feature == "ipv6-nodes-v1" {
			previouslyRequired = true
		}
	}
	set := func(required bool) error {
		current, err := loadHost(p)
		if err != nil {
			return err
		}
		features := make([]string, 0, len(current.RequiredFeatures)+1)
		present := false
		for _, feature := range current.RequiredFeatures {
			if feature == "ipv6-nodes-v1" {
				present = true
				continue
			}
			features = append(features, feature)
		}
		if present == required {
			return nil
		}
		if required {
			features = append(features, "ipv6-nodes-v1")
		}
		sort.Strings(features)
		current.RequiredFeatures = features
		return saveHost(p, current)
	}
	if err := set(previouslyRequired || next.IPv6Nodes != nil); err != nil {
		return nil, nil, err
	}
	return func() error { return set(next.IPv6Nodes != nil) }, func() error { return set(previouslyRequired) }, nil
}
