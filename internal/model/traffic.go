package model

import "math"

// Zero is the legacy/default representation of 1x.
func (c Config) EffectiveTrafficMultiplier() int {
	if c.TrafficMultiplier == 2 {
		return 2
	}
	return 1
}

// TrafficUsage converts raw proxy counters for display only. Unsigned arithmetic
// can represent twice any valid (nonnegative int64) raw counter exactly.
func (c Config) TrafficUsage(upload, download int64) (uint64, uint64) {
	multiplier := uint64(c.EffectiveTrafficMultiplier())
	return uint64(upload) * multiplier, uint64(download) * multiplier
}

// Saturate the combined display value instead of wrapping on extreme counters.
func TrafficTotal(upload, download uint64) uint64 {
	if download > math.MaxUint64-upload {
		return math.MaxUint64
	}
	return upload + download
}
