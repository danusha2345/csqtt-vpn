package core

import "sync/atomic"

// Payload bytes successfully forwarded through the bridge, not wire overhead.
type trafficCounters struct{ down, up atomic.Int64 }

func (c *trafficCounters) snapshot() (int64, int64) { return c.down.Load(), c.up.Load() }
