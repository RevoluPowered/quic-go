//go:build windows

package quic

import (
	"net"

	"golang.org/x/net/ipv4"
)

// windowsBatchConn implements batchConn using Go's native ReadMsgUDP.
// Windows has no sendmmsg/recvmsg_x, and x/net's ReadBatch/WriteBatch
// are not implemented on Windows. Go's net.UDPConn.ReadMsgUDP handles
// IOCP correctly and returns OOB control data (ECN, pktinfo) when
// the appropriate socket options are set.
type windowsBatchConn struct {
	conn *net.UDPConn
}

func newWindowsBatchConn(c OOBCapablePacketConn) (*windowsBatchConn, error) {
	// Extract the underlying *net.UDPConn for ReadMsgUDP.
	type udpConnGetter interface {
		ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	}
	if _, ok := c.(udpConnGetter); !ok {
		return nil, net.UnknownNetworkError("not a UDPConn")
	}
	// OOBCapablePacketConn embeds WriteMsgUDP; we need the concrete *net.UDPConn
	// for ReadMsgUDP which is the Go-native IOCP-aware read path.
	udpConn, ok := c.(*net.UDPConn)
	if !ok {
		return nil, net.UnknownNetworkError("not a *net.UDPConn")
	}
	return &windowsBatchConn{conn: udpConn}, nil
}

// ReadBatch reads one packet at a time using Go's native ReadMsgUDP.
// No kernel-level batching exists on Windows, but this correctly handles
// IOCP and populates OOB control data for ECN/pktinfo.
func (c *windowsBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if len(ms) == 0 {
		return 0, nil
	}
	msg := &ms[0]

	// Use Go's native ReadMsgUDP which handles IOCP correctly.
	n, oobn, readFlags, addr, err := c.conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
	if err != nil {
		return 0, err
	}
	msg.N = n
	msg.NN = oobn
	msg.Flags = readFlags
	msg.Addr = addr
	return 1, nil
}

// WriteBatch writes multiple packets using Go's native WriteMsgUDP.
func (c *windowsBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	for i := range ms {
		var addr *net.UDPAddr
		if ms[i].Addr != nil {
			addr = ms[i].Addr.(*net.UDPAddr)
		}
		n, _, err := c.conn.WriteMsgUDP(ms[i].Buffers[0], ms[i].OOB, addr)
		if err != nil {
			if i == 0 {
				return 0, err
			}
			return i, nil
		}
		ms[i].N = n
	}
	return len(ms), nil
}

func newBatchConn(c OOBCapablePacketConn) batchConn {
	bc, err := newWindowsBatchConn(c)
	if err != nil {
		// Shouldn't happen with a real UDPConn, but fall back gracefully.
		return ipv4.NewPacketConn(c)
	}
	return bc
}
