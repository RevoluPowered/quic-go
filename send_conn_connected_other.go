//go:build !darwin

package quic

// connectSharedSocket is a no-op on non-Darwin platforms.
// The pru_sosend_list fast path is macOS/XNU specific.
func (c *sconn) connectSharedSocket() {}
