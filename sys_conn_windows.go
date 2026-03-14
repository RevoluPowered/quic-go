//go:build windows

package quic

import (
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	ecnMask       = 0x3
	oobBufferSize = 128
)

type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

func inspectReadBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func inspectWriteBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func isECNDisabledUsingEnv() bool {
	disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN"))
	return err == nil && disabled
}

type oobConn struct {
	OOBCapablePacketConn
	batchConn batchConn

	readPos  uint8
	messages []ipv4.Message
	buffers  [batchSize]*packetBuffer

	cap connCapabilities
}

var _ rawConn = &oobConn{}

func newConn(c OOBCapablePacketConn, supportsDF bool) (*oobConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	var needsPacketInfo bool
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}

	// Enable ECN and packet info socket options.
	// On Windows, we use IP_ECN/IPV6_ECN (value 50) for ECN support.
	// Try both IPv4 and IPv6; at least one should succeed.
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		errECNIPv4 = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipECN, 1)
		errECNIPv6 = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6ECN, 1)

		if needsPacketInfo {
			errPIIPv4 = windows.SetsockoptInt(h, windows.IPPROTO_IP, windows.IP_PKTINFO, 1)
			errPIIPv6 = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1)
		}
	}); err != nil {
		return nil, err
	}

	ecnEnabled := errECNIPv4 == nil || errECNIPv6 == nil
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Failed to activate ECN for both IPv4 and IPv6, ECN disabled.")
	}

	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Failed to activate packet info for both IPv4 and IPv6.")
		}
	}

	var bc batchConn
	if ibc, ok := c.(batchConn); ok {
		bc = ibc
	} else {
		bc = newBatchConn(c)
	}

	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}
	oob := &oobConn{
		OOBCapablePacketConn: c,
		batchConn:            bc,
		messages:             msgs,
		readPos:              batchSize,
		cap: connCapabilities{
			DF:  supportsDF,
			GSO: false,
			ECN: ecnEnabled && isECNEnabled(),
		},
	}
	for i := 0; i < batchSize; i++ {
		oob.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return oob, nil
}

var invalidCmsgOnceV4, invalidCmsgOnceV6 sync.Once

func (c *oobConn) ReadPacket() (receivedPacket, error) {
	if len(c.messages) == int(c.readPos) {
		c.messages = c.messages[:batchSize]
		for i := uint8(0); i < c.readPos; i++ {
			buffer := getPacketBuffer()
			buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
			c.buffers[i] = buffer
			c.messages[i].Buffers[0] = c.buffers[i].Data
		}
		c.readPos = 0

		n, err := c.batchConn.ReadBatch(c.messages, 0)
		if n == 0 || err != nil {
			return receivedPacket{}, err
		}
		c.messages = c.messages[:n]
	}

	msg := c.messages[c.readPos]
	buffer := c.buffers[c.readPos]
	c.readPos++

	data := msg.OOB[:msg.NN]
	p := receivedPacket{
		remoteAddr: msg.Addr,
		rcvTime:    monotime.Now(),
		data:       msg.Buffers[0][:msg.N],
		buffer:     buffer,
	}

	// Parse Windows WSACMSGHDR control messages.
	for len(data) > 0 {
		hdr, body, remainder, err := parseOneWSAControlMessage(data)
		if err != nil {
			break
		}
		if hdr.Level == syscall.IPPROTO_IP {
			switch hdr.Type {
			case ipECN:
				if len(body) >= 4 {
					ecnBits := uint8(binary.NativeEndian.Uint32(body)) & ecnMask
					p.ecn = protocol.ParseECNHeaderBits(ecnBits)
				}
			case int32(windows.IP_PKTINFO):
				ip, ifIndex, ok := parseIPv4PktInfo(body)
				if ok {
					p.info.addr = ip
					p.info.ifIndex = ifIndex
				} else {
					invalidCmsgOnceV4.Do(func() {
						log.Printf("Received invalid IPv4 packet info control message: %+x. "+
							"This should never occur, please open a new issue.", body)
					})
				}
			}
		}
		if hdr.Level == syscall.IPPROTO_IPV6 {
			switch hdr.Type {
			case ipv6ECN:
				if len(body) >= 4 {
					ecnBits := uint8(binary.NativeEndian.Uint32(body)) & ecnMask
					p.ecn = protocol.ParseECNHeaderBits(ecnBits)
				}
			case int32(windows.IPV6_PKTINFO):
				// IN6_PKTINFO: Addr [16]byte, Ifindex uint32
				if len(body) == 20 {
					p.info.addr = netip.AddrFrom16(*(*[16]byte)(body[:16])).Unmap()
					p.info.ifIndex = binary.NativeEndian.Uint32(body[16:])
				} else {
					invalidCmsgOnceV6.Do(func() {
						log.Printf("Received invalid IPv6 packet info control message: %+x. "+
							"This should never occur, please open a new issue.", body)
					})
				}
			}
		}
		data = remainder
	}
	return p, nil
}

func (c *oobConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	oob := packetInfoOOB
	if ecn != protocol.ECNUnsupported {
		if !c.capabilities().ECN {
			panic("tried to send an ECN-marked packet although ECN is disabled")
		}
		if remoteUDPAddr, ok := addr.(*net.UDPAddr); ok {
			if remoteUDPAddr.IP.To4() != nil {
				oob = appendIPv4ECNMsg(oob, ecn)
			} else {
				oob = appendIPv6ECNMsg(oob, ecn)
			}
		}
	}
	n, _, err := c.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
	return n, err
}

func (c *oobConn) capabilities() connCapabilities {
	return c.cap
}

type packetInfo struct {
	addr    netip.Addr
	ifIndex uint32
}

func (info *packetInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if info.addr.Is4() {
		ip := info.addr.As4()
		// Build IN_PKTINFO control message for WSASendMsg.
		// IN_PKTINFO: Addr [4]byte, Ifindex uint32
		const dataLen = 8
		b := make([]byte, wsaCmsgSpace(dataLen))
		h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[0]))
		h.Level = syscall.IPPROTO_IP
		h.Type = int32(windows.IP_PKTINFO)
		h.Len = wsaCmsgLen(dataLen)
		offset := int(wsaCmsgData())
		copy(b[offset:offset+4], ip[:])
		binary.NativeEndian.PutUint32(b[offset+4:offset+8], info.ifIndex)
		return b
	} else if info.addr.Is6() {
		ip := info.addr.As16()
		// Build IN6_PKTINFO control message for WSASendMsg.
		// IN6_PKTINFO: Addr [16]byte, Ifindex uint32
		const dataLen = 20
		b := make([]byte, wsaCmsgSpace(dataLen))
		h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[0]))
		h.Level = syscall.IPPROTO_IPV6
		h.Type = int32(windows.IPV6_PKTINFO)
		h.Len = wsaCmsgLen(dataLen)
		offset := int(wsaCmsgData())
		copy(b[offset:offset+16], ip[:])
		binary.NativeEndian.PutUint32(b[offset+16:offset+20], info.ifIndex)
		return b
	}
	return nil
}
