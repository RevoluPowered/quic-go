//go:build darwin

package quic

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// connectSharedSocket connect()'s the shared rawConn's underlying UDP socket
// to the remote peer. After this, writes with nil addr (msg_name=NULL) will
// hit XNU's pru_sosend_list fast path in sendmsg_x for true kernel-level
// batch UDP I/O.
//
// This should only be called for single-use transports (DialAddr) where the
// shared socket serves exactly one QUIC connection. Connecting the socket
// filters incoming packets to the connected peer, which is the desired
// behavior for a single-connection client.
//
// Note: we cannot use Go's WriteMsgUDP(b, oob, nil) after connecting via raw fd,
// because Go checks fd.isConnected internally and returns errMissingAddress.
// All connected writes go through darwinBatchConn.WriteBatch (raw sendmsg_x).
func (c *sconn) connectSharedSocket() {
	oobC, ok := c.rawConn.(*oobConn)
	if !ok {
		return
	}

	udpConn, ok := oobC.OOBCapablePacketConn.(*net.UDPConn)
	if !ok {
		return
	}

	// Need darwinBatchConn for raw sendmsg_x writes.
	type batchWriter interface {
		WriteBatch(ms []ipv4.Message, flags int) (int, error)
	}
	bw, ok := oobC.batchConn.(batchWriter)
	if !ok {
		return
	}

	ai := c.remoteAddrInfo.Load()
	udpAddr, ok := ai.addr.(*net.UDPAddr)
	if !ok {
		return
	}

	rawSock, err := udpConn.SyscallConn()
	if err != nil {
		return
	}

	isIPv4 := udpAddr.IP.To4() != nil

	// Detect if the socket is IPv6 (dual-stack).
	// A dual-stack socket needs IPv4-mapped-IPv6 sockaddr for IPv4 destinations.
	var socketIsIPv6 bool
	if localAddr, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		socketIsIPv6 = localAddr.IP.To4() == nil
	}

	var connectErr error
	if err := rawSock.Control(func(fd uintptr) {
		if isIPv4 && !socketIsIPv6 {
			sa := &unix.SockaddrInet4{Port: udpAddr.Port}
			copy(sa.Addr[:], udpAddr.IP.To4())
			connectErr = unix.Connect(int(fd), sa)
		} else {
			// IPv6 destination, or IPv4 destination on dual-stack socket
			// (needs IPv4-mapped IPv6: ::ffff:x.x.x.x)
			sa := &unix.SockaddrInet6{Port: udpAddr.Port}
			copy(sa.Addr[:], udpAddr.IP.To16())
			if udpAddr.Zone != "" {
				if ifi, err := net.InterfaceByName(udpAddr.Zone); err == nil {
					sa.ZoneId = uint32(ifi.Index)
				}
			}
			connectErr = unix.Connect(int(fd), sa)
		}
	}); err != nil {
		return
	}
	if connectErr != nil {
		return
	}

	c.isConnected = true
	c.isIPv4 = isIPv4
	c.batchWriter = bw
}
