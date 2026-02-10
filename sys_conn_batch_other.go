//go:build linux || freebsd

package quic

import "golang.org/x/net/ipv4"

func newBatchConn(c OOBCapablePacketConn) batchConn {
	return ipv4.NewPacketConn(c)
}
