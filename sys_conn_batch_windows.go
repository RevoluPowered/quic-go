//go:build windows

package quic

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
)

// windowsBatchConn implements batchConn using WSARecvMsg / WSASendMsg.
// There is no kernel-level batching on Windows (no sendmmsg/recvmsg_x),
// but we still benefit from:
//   - Bypassing Go's net package per-call overhead
//   - Buffer reuse (no alloc per packet)
//   - OOB/control data support (ECN, pktinfo)
//   - Drain loop: after the first blocking WSARecvMsg, we non-blocking drain
//     any additional queued packets before returning.
type windowsBatchConn struct {
	fd      windows.Handle
	rawConn syscall.RawConn
	isIPv6  bool

	// Pre-allocated receive buffers.
	rSockaddrs [batchSize]syscall.RawSockaddrAny
}

func newWindowsBatchConn(c OOBCapablePacketConn) (*windowsBatchConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd windows.Handle
	if err := rawConn.Control(func(fdp uintptr) {
		fd = windows.Handle(fdp)
	}); err != nil {
		return nil, err
	}

	var isIPv6 bool
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
		isIPv6 = addr.IP.To4() == nil
	}

	return &windowsBatchConn{
		fd:      fd,
		rawConn: rawConn,
		isIPv6:  isIPv6,
	}, nil
}

// ReadBatch reads up to len(ms) packets. The first read blocks; subsequent
// reads are non-blocking to drain any queued packets.
func (c *windowsBatchConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n := len(ms)
	if n > batchSize {
		n = batchSize
	}
	if n == 0 {
		return 0, nil
	}

	// First read: blocking.
	nread, err := c.readOne(&ms[0], 0, true)
	if err != nil {
		return 0, err
	}
	if nread == 0 {
		return 0, nil
	}
	total := 1

	// Drain loop: non-blocking reads for any additional queued packets.
	for i := 1; i < n; i++ {
		nread, err = c.readOne(&ms[i], total, false)
		if err != nil || nread == 0 {
			break
		}
		total++
	}

	return total, nil
}

// readOne performs a single WSARecvMsg call.
// If blocking is false and the socket would block, it returns (0, nil).
func (c *windowsBatchConn) readOne(msg *ipv4.Message, idx int, blocking bool) (int, error) {
	sa := &c.rSockaddrs[idx]
	*sa = syscall.RawSockaddrAny{}

	wsaMsg := windows.WSAMsg{
		Name:    sa,
		Namelen: int32(unsafe.Sizeof(*sa)),
	}

	// Set up data buffer.
	wsaBuf := windows.WSABuf{
		Buf: &msg.Buffers[0][0],
		Len: uint32(len(msg.Buffers[0])),
	}
	wsaMsg.Buffers = &wsaBuf
	wsaMsg.BufferCount = 1

	// Set up control/OOB buffer.
	if len(msg.OOB) > 0 {
		wsaMsg.Control = windows.WSABuf{
			Buf: &msg.OOB[0],
			Len: uint32(len(msg.OOB)),
		}
	}

	var bytesReceived uint32
	var operr error

	readFn := func(fd uintptr) bool {
		operr = windows.WSARecvMsg(windows.Handle(fd), &wsaMsg, &bytesReceived, nil, nil)
		if operr != nil {
			if errno, ok := operr.(syscall.Errno); ok {
				if errno == syscall.EWOULDBLOCK || errno == windows.WSAEWOULDBLOCK {
					if blocking {
						return false // let Go runtime park on IOCP
					}
					operr = nil // non-blocking: not an error, just no data
					return true
				}
			}
			return true
		}
		return true
	}

	if blocking {
		if err := c.rawConn.Read(readFn); err != nil {
			return 0, err
		}
	} else {
		// For non-blocking drain, use Control so we don't block.
		if err := c.rawConn.Control(func(fd uintptr) {
			readFn(fd)
		}); err != nil {
			return 0, err
		}
	}

	if operr != nil {
		return 0, os.NewSyscallError("wsarecvmsg", operr)
	}
	if bytesReceived == 0 && !blocking {
		return 0, nil
	}

	msg.N = int(bytesReceived)
	msg.NN = int(wsaMsg.Control.Len)
	msg.Flags = int(wsaMsg.Flags)

	addr, err := rawSockaddrToUDPAddr(sa)
	if err != nil {
		return 0, err
	}
	msg.Addr = addr

	return 1, nil
}

// WriteBatch writes multiple packets using WSASendMsg in a tight loop.
func (c *windowsBatchConn) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	for i := range ms {
		if err := c.writeOne(&ms[i]); err != nil {
			if i == 0 {
				return 0, err
			}
			return i, nil
		}
	}
	return len(ms), nil
}

// writeOne performs a single WSASendMsg call.
func (c *windowsBatchConn) writeOne(msg *ipv4.Message) error {
	var wsaMsg windows.WSAMsg

	// Marshal destination address.
	var sa syscall.RawSockaddrAny
	var saLen int32
	if msg.Addr != nil {
		var err error
		saLen, err = marshalWindowsSockaddr(msg.Addr, &sa, c.isIPv6)
		if err != nil {
			return err
		}
		wsaMsg.Name = &sa
		wsaMsg.Namelen = saLen
	}

	wsaBuf := windows.WSABuf{
		Buf: &msg.Buffers[0][0],
		Len: uint32(len(msg.Buffers[0])),
	}
	wsaMsg.Buffers = &wsaBuf
	wsaMsg.BufferCount = 1

	if len(msg.OOB) > 0 {
		wsaMsg.Control = windows.WSABuf{
			Buf: &msg.OOB[0],
			Len: uint32(len(msg.OOB)),
		}
	}

	var bytesSent uint32
	var operr error

	err := c.rawConn.Write(func(fd uintptr) bool {
		operr = windows.WSASendMsg(windows.Handle(fd), &wsaMsg, 0, &bytesSent, nil, nil)
		if operr != nil {
			if errno, ok := operr.(syscall.Errno); ok {
				if errno == syscall.EWOULDBLOCK || errno == windows.WSAEWOULDBLOCK {
					return false // let Go runtime park on IOCP
				}
			}
			return true
		}
		return true
	})
	if err != nil {
		return err
	}
	if operr != nil {
		return os.NewSyscallError("wsasendmsg", operr)
	}
	msg.N = int(bytesSent)
	return nil
}

func newBatchConn(c OOBCapablePacketConn) batchConn {
	bc, err := newWindowsBatchConn(c)
	if err != nil {
		return ipv4.NewPacketConn(c)
	}
	return bc
}

// rawSockaddrToUDPAddr converts a RawSockaddrAny to a *net.UDPAddr.
func rawSockaddrToUDPAddr(rsa *syscall.RawSockaddrAny) (*net.UDPAddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:]))
		ip := make(net.IP, net.IPv4len)
		copy(ip, sa.Addr[:])
		return &net.UDPAddr{IP: ip, Port: port}, nil
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:]))
		ip := make(net.IP, net.IPv6len)
		copy(ip, sa.Addr[:])
		var zone string
		if sa.Scope_id != 0 {
			if ifi, err := net.InterfaceByIndex(int(sa.Scope_id)); err == nil {
				zone = ifi.Name
			}
		}
		return &net.UDPAddr{IP: ip, Port: port, Zone: zone}, nil
	default:
		return nil, fmt.Errorf("unsupported address family: %d", rsa.Addr.Family)
	}
}

// marshalWindowsSockaddr writes a net.Addr into a RawSockaddrAny.
// If forceIPv6 is true, IPv4 addresses are mapped to IPv6.
// Returns the sockaddr length and any error.
func marshalWindowsSockaddr(addr net.Addr, rsa *syscall.RawSockaddrAny, forceIPv6 bool) (int32, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("unsupported address type: %T", addr)
	}

	if ip4 := udpAddr.IP.To4(); ip4 != nil && !forceIPv6 {
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa.Family = syscall.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&sa.Port))
		binary.BigEndian.PutUint16(p[:], uint16(udpAddr.Port))
		copy(sa.Addr[:], ip4)
		return int32(unsafe.Sizeof(*sa)), nil
	}

	ip6 := udpAddr.IP.To16()
	if ip6 == nil {
		return 0, fmt.Errorf("invalid IP address: %v", udpAddr.IP)
	}
	sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
	sa.Family = syscall.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	binary.BigEndian.PutUint16(p[:], uint16(udpAddr.Port))
	copy(sa.Addr[:], ip6)
	if udpAddr.Zone != "" {
		if ifi, err := net.InterfaceByName(udpAddr.Zone); err == nil {
			sa.Scope_id = uint32(ifi.Index)
		}
	}
	return int32(unsafe.Sizeof(*sa)), nil
}
