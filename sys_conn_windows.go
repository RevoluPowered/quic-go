//go:build windows

package quic

import (
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/quic-go/quic-go/internal/protocol"
)

func newConn(c OOBCapablePacketConn, supportsDF bool) (*basicConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF}, nil
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

type packetInfo struct {
	addr netip.Addr
}

func (i *packetInfo) OOB() []byte { return nil }

// Stubs for non-OOB platforms. writeConnected in send_conn.go references these
// but is never called on Windows (connectSharedSocket is a no-op on non-Darwin).
func appendIPv4ECNMsg(b []byte, _ protocol.ECN) []byte { return b }
func appendIPv6ECNMsg(b []byte, _ protocol.ECN) []byte { return b }
