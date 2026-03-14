//go:build windows

package quic

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	// batchSize is the number of messages to read/write per batch.
	// Windows has no sendmmsg/recvmmsg, but we still batch at the Go level
	// to amortize ReadBatch overhead (drain loop after first blocking read).
	batchSize = 8

	// IP_ECN / IPV6_ECN control message type for reading/writing ECN bits.
	// Available since Windows 10 1903 (build 18362).
	// Not yet in x/sys/windows, so we define them here.
	ipECN   = 50
	ipv6ECN = 50

	// msgTypeIPTOS is the cmsg type for IPv4 ECN/TOS on Windows.
	// Windows uses IP_ECN (50) to receive ECN bits, not IP_TOS/IP_RECVTOS.
	msgTypeIPTOS = ipECN

	// ecnIPv4DataLen is the size of the ECN cmsg data for IPv4 on Windows.
	// Windows returns ECN as a 4-byte INT.
	ecnIPv4DataLen = 4
)

func isGSOEnabled(syscall.RawConn) bool { return false }
func isECNEnabled() bool               { return !isECNDisabledUsingEnv() }

func forceSetReceiveBuffer(c any, bytes int) error { return nil }
func forceSetSendBuffer(c any, bytes int) error    { return nil }

func appendUDPSegmentSizeMsg(b []byte, _ uint16) []byte { return b }
func isGSOError(error) bool                             { return false }
func isPermissionError(error) bool                      { return false }

// wsaCmsgAlign rounds a length up to pointer-size alignment.
// Windows WSACMSGHDR uses pointer-size alignment (8 bytes on 64-bit).
func wsaCmsgAlign(length uintptr) uintptr {
	const alignTo = unsafe.Sizeof(uintptr(0))
	return (length + alignTo - 1) &^ (alignTo - 1)
}

// wsaCmsgSpace returns the total space needed for a control message
// with the given data length, including header and alignment padding.
func wsaCmsgSpace(dataLen uintptr) uintptr {
	return wsaCmsgAlign(unsafe.Sizeof(windows.WSACMSGHDR{})) + wsaCmsgAlign(dataLen)
}

// wsaCmsgLen returns the value for WSACMSGHDR.Len given the data length.
// Includes header but not trailing alignment.
func wsaCmsgLen(dataLen uintptr) uintptr {
	return unsafe.Sizeof(windows.WSACMSGHDR{}) + dataLen
}

// wsaCmsgData returns the offset from the start of a WSACMSGHDR to its data.
func wsaCmsgData() uintptr {
	return wsaCmsgAlign(unsafe.Sizeof(windows.WSACMSGHDR{}))
}

// parseIPv4PktInfo parses a Windows IN_PKTINFO structure from control message body.
func parseIPv4PktInfo(body []byte) (ip netip.Addr, ifIndex uint32, ok bool) {
	// windows.IN_PKTINFO: Addr [4]byte, Ifindex uint32
	if len(body) < 8 {
		return netip.Addr{}, 0, false
	}
	addr := netip.AddrFrom4(*(*[4]byte)(body[:4]))
	idx := binary.NativeEndian.Uint32(body[4:8])
	return addr, idx, true
}

// parseOneWSAControlMessage parses a single WSACMSGHDR from the given buffer.
// Returns the header, message body, remaining data, and any error.
func parseOneWSAControlMessage(b []byte) (hdr windows.WSACMSGHDR, body []byte, remainder []byte, err error) {
	hdrSize := unsafe.Sizeof(windows.WSACMSGHDR{})
	if uintptr(len(b)) < hdrSize {
		return hdr, nil, nil, syscall.EINVAL
	}

	hdr = *(*windows.WSACMSGHDR)(unsafe.Pointer(&b[0]))
	if hdr.Len < hdrSize || uintptr(hdr.Len) > uintptr(len(b)) {
		return hdr, nil, nil, syscall.EINVAL
	}

	dataStart := wsaCmsgData()
	dataEnd := uintptr(hdr.Len)
	if dataStart > dataEnd {
		return hdr, nil, nil, syscall.EINVAL
	}
	body = b[dataStart:dataEnd]

	next := wsaCmsgAlign(uintptr(hdr.Len))
	if next >= uintptr(len(b)) {
		remainder = nil
	} else {
		remainder = b[next:]
	}
	return hdr, body, remainder, nil
}

// appendIPv4ECNMsg appends a WSACMSGHDR for setting IPv4 ECN bits via WSASendMsg.
func appendIPv4ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	space := wsaCmsgSpace(uintptr(ecnIPv4DataLen))
	b = append(b, make([]byte, space)...)
	h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IP
	h.Type = ipECN
	h.Len = wsaCmsgLen(ecnIPv4DataLen)

	offset := startLen + int(wsaCmsgData())
	binary.NativeEndian.PutUint32(b[offset:offset+ecnIPv4DataLen], uint32(val.ToHeaderBits()))
	return b
}

// appendIPv6ECNMsg appends a WSACMSGHDR for setting IPv6 ECN bits via WSASendMsg.
func appendIPv6ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	const dataLen = 4
	space := wsaCmsgSpace(uintptr(dataLen))
	b = append(b, make([]byte, space)...)
	h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IPV6
	h.Type = ipv6ECN
	h.Len = wsaCmsgLen(dataLen)

	offset := startLen + int(wsaCmsgData())
	binary.NativeEndian.PutUint32(b[offset:offset+dataLen], uint32(val.ToHeaderBits()))
	return b
}
