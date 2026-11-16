package cli

import "nodekit/internal/model"

// Persist the capability before changing listeners/rules. Older root helpers
// already honor arbitrary RequiredFeatures strings, even if they do not know
// how to decode the new Config field or an interrupted candidate.
func beginIPv6Requirement(p paths, old, next model.Config) (func() error, func() error, error) {
	return beginFeatureRequirement(p, "ipv6-nodes-v1", old.IPv6Nodes != nil, next.IPv6Nodes != nil)
}
