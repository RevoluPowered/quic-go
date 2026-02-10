//go:build darwin

package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// msghdrX mirrors struct msghdr_x from <sys/socket.h> on Darwin.
// It extends the standard msghdr with a msg_datalen field.
// On recv, the kernel sets Datalen to the number of bytes received.
// On send, the kernel ignores Datalen.
type msghdrX struct {
	Name       *byte
	Namelen    uint32
	Iov        *unix.Iovec
	Iovlen     int32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

// Compile-time size assertion: msghdrX must be 56 bytes on arm64/amd64.
var _ [56]byte = [unsafe.Sizeof(msghdrX{})]byte{}

// darwinBatchConn implements batchConn using sendmsg_x/recvmsg_x syscalls
// for batched UDP I/O on macOS.
type darwinBatchConn struct {
	fd      int
	rawConn syscall.RawConn

	// isIPv6 is true when the underlying socket is AF_INET6 (dual-stack).
	// When true, IPv4 addresses are sent as IPv4-mapped IPv6 (::ffff:x.x.x.x)
	// in sockaddr_in6, since sendmsg_x on an IPv6 socket rejects sockaddr_in.
	isIPv6 bool

	// Pre-allocated buffers to avoid per-call allocation.
	rMsghdrs   [batchSize]msghdrX
	rIovecs    [batchSize]unix.Iovec
	rSockaddrs [batchSize][unix.SizeofSockaddrInet6]byte
}

func newDarwinBatchConn(c OOBCapablePacketConn) (*darwinBatchConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	if err := rawConn.Control(func(fdp uintptr) {
		fd = int(fdp)
	}); err != nil {
		return nil, err
	}

	// Detect if the socket is IPv6 (dual-stack).
	var isIPv6 bool
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
		// A dual-stack socket ("udp" with IPv4zero) has a local addr like [::]:port.
		// An IPv4-only socket ("udp4") has a local addr like 0.0.0.0:port or 127.0.0.1:port.
		isIPv6 = addr.IP.To4() == nil
	}

	return &darwinBatchConn{
		fd:      fd,
		rawConn: rawConn,
		isIPv6:  isIPv6,
	}, nil
}

// ReadBatch reads up to len(ms) packets using recvmsg_x.
func (c *darwinBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n := len(ms)
	if n > batchSize {
		n = batchSize
	}
	if n == 0 {
		return 0, nil
	}

	// Set up msghdrX array pointing into the ipv4.Message buffers.
	for i := 0; i < n; i++ {
		c.rIovecs[i] = unix.Iovec{
			Base: &ms[i].Buffers[0][0],
		}
		c.rIovecs[i].SetLen(len(ms[i].Buffers[0]))
		c.rMsghdrs[i] = msghdrX{
			Name:    &c.rSockaddrs[i][0],
			Namelen: unix.SizeofSockaddrInet6,
			Iov:     &c.rIovecs[i],
			Iovlen:  1,
		}
		if len(ms[i].OOB) > 0 {
			c.rMsghdrs[i].Control = &ms[i].OOB[0]
			c.rMsghdrs[i].Controllen = uint32(len(ms[i].OOB))
		}
	}

	var operr error
	var nrecv int
	err := c.rawConn.Read(func(fd uintptr) bool {
		r1, _, errno := syscall.Syscall6(
			unix.SYS_RECVMSG_X,
			fd,
			uintptr(unsafe.Pointer(&c.rMsghdrs[0])),
			uintptr(n),
			uintptr(flags),
			0, 0,
		)
		if errno != 0 {
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
				return false // not ready, let Go park goroutine on kqueue
			}
			operr = errno
			return true
		}
		nrecv = int(r1)
		return true
	})
	if err != nil {
		return 0, err
	}
	if operr != nil {
		return 0, os.NewSyscallError("recvmsg_x", operr)
	}

	// Unpack results into ipv4.Message.
	for i := 0; i < nrecv; i++ {
		ms[i].N = int(c.rMsghdrs[i].Datalen)
		ms[i].NN = int(c.rMsghdrs[i].Controllen)
		ms[i].Flags = int(c.rMsghdrs[i].Flags)
		addr, err := parseSockaddr(c.rSockaddrs[i][:c.rMsghdrs[i].Namelen])
		if err != nil {
			return i, err
		}
		ms[i].Addr = addr
	}

	return nrecv, nil
}

// WriteBatch writes multiple packets using sendmsg_x.
func (c *darwinBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	n := len(ms)
	if n == 0 {
		return 0, nil
	}

	// Allocate per-call (these contain per-message pointers, can't easily pre-alloc).
	hdrs := make([]msghdrX, n)
	iovs := make([]unix.Iovec, n)
	sas := make([][unix.SizeofSockaddrInet6]byte, n)

	for i := 0; i < n; i++ {
		iovs[i] = unix.Iovec{
			Base: &ms[i].Buffers[0][0],
		}
		iovs[i].SetLen(len(ms[i].Buffers[0]))

		saLen := marshalSockaddr(ms[i].Addr, sas[i][:], c.isIPv6)
		hdrs[i] = msghdrX{
			Iov:    &iovs[i],
			Iovlen: 1,
		}
		if saLen > 0 {
			hdrs[i].Name = &sas[i][0]
			hdrs[i].Namelen = uint32(saLen)
		}
		if len(ms[i].OOB) > 0 {
			hdrs[i].Control = &ms[i].OOB[0]
			hdrs[i].Controllen = uint32(len(ms[i].OOB))
		}
	}

	var operr error
	var nsent int
	err := c.rawConn.Write(func(fd uintptr) bool {
		r1, _, errno := syscall.Syscall6(
			unix.SYS_SENDMSG_X,
			fd,
			uintptr(unsafe.Pointer(&hdrs[0])),
			uintptr(n),
			uintptr(flags),
			0, 0,
		)
		if errno != 0 {
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
				return false // not ready, let Go park goroutine on kqueue
			}
			operr = errno
			return true
		}
		nsent = int(r1)
		return true
	})
	if err != nil {
		return 0, err
	}
	if operr != nil {
		return 0, os.NewSyscallError("sendmsg_x", operr)
	}

	for i := 0; i < nsent; i++ {
		ms[i].N = int(hdrs[i].Datalen)
	}
	return nsent, nil
}

func newBatchConn(c OOBCapablePacketConn) batchConn {
	bc, err := newDarwinBatchConn(c)
	if err != nil {
		// Fall back to standard x/net ipv4 (single-message per call).
		return ipv4.NewPacketConn(c)
	}
	return bc
}

// parseSockaddr parses a BSD-format sockaddr into a net.UDPAddr.
// BSD sockaddr format: b[0]=len, b[1]=family.
func parseSockaddr(b []byte) (net.Addr, error) {
	if len(b) < 2 {
		return nil, errors.New("short sockaddr")
	}
	family := b[1]
	switch family {
	case syscall.AF_INET:
		if len(b) < unix.SizeofSockaddrInet4 {
			return nil, fmt.Errorf("short sockaddr_in: got %d, want %d", len(b), unix.SizeofSockaddrInet4)
		}
		port := int(binary.BigEndian.Uint16(b[2:4]))
		ip := make(net.IP, net.IPv4len)
		copy(ip, b[4:8])
		return &net.UDPAddr{IP: ip, Port: port}, nil
	case syscall.AF_INET6:
		if len(b) < unix.SizeofSockaddrInet6 {
			return nil, fmt.Errorf("short sockaddr_in6: got %d, want %d", len(b), unix.SizeofSockaddrInet6)
		}
		port := int(binary.BigEndian.Uint16(b[2:4]))
		ip := make(net.IP, net.IPv6len)
		copy(ip, b[8:24])
		var zone string
		scopeID := binary.NativeEndian.Uint32(b[24:28])
		if scopeID != 0 {
			if ifi, err := net.InterfaceByIndex(int(scopeID)); err == nil {
				zone = ifi.Name
			}
		}
		return &net.UDPAddr{IP: ip, Port: port, Zone: zone}, nil
	default:
		return nil, fmt.Errorf("unsupported address family: %d", family)
	}
}

// marshalSockaddr writes a net.UDPAddr into a BSD-format sockaddr buffer.
// If forceIPv6 is true, IPv4 addresses are written as IPv4-mapped IPv6
// (::ffff:x.x.x.x) in a sockaddr_in6 structure. This is required when the
// underlying socket is AF_INET6 (dual-stack), since sendmsg_x rejects
// sockaddr_in (AF_INET) on an IPv6 socket.
// Returns the number of bytes written.
func marshalSockaddr(addr net.Addr, b []byte, forceIPv6 bool) int {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0
	}
	if ip4 := udpAddr.IP.To4(); ip4 != nil && !forceIPv6 {
		// struct sockaddr_in: len, family, port, addr, zero
		b[0] = unix.SizeofSockaddrInet4
		b[1] = syscall.AF_INET
		binary.BigEndian.PutUint16(b[2:4], uint16(udpAddr.Port))
		copy(b[4:8], ip4)
		// zero out sin_zero
		for i := 8; i < unix.SizeofSockaddrInet4; i++ {
			b[i] = 0
		}
		return unix.SizeofSockaddrInet4
	}
	// IPv6, or IPv4-mapped-to-IPv6 for dual-stack sockets.
	ip6 := udpAddr.IP.To16()
	if ip6 == nil {
		return 0
	}
	// struct sockaddr_in6: len, family, port, flowinfo, addr, scope_id
	b[0] = unix.SizeofSockaddrInet6
	b[1] = syscall.AF_INET6
	binary.BigEndian.PutUint16(b[2:4], uint16(udpAddr.Port))
	// flowinfo = 0
	b[4], b[5], b[6], b[7] = 0, 0, 0, 0
	copy(b[8:24], ip6)
	// scope_id
	var scopeID uint32
	if udpAddr.Zone != "" {
		if ifi, err := net.InterfaceByName(udpAddr.Zone); err == nil {
			scopeID = uint32(ifi.Index)
		}
	}
	binary.NativeEndian.PutUint32(b[24:28], scopeID)
	return unix.SizeofSockaddrInet6
}
