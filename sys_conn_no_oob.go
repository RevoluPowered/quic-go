//go:build !darwin && !linux && !freebsd && !windows

package quic

import (
	"net"
	"net/netip"

	"github.com/quic-go/quic-go/internal/protocol"
)

func newConn(c net.PacketConn, supportsDF bool) (*basicConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF}, nil
}

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }

type packetInfo struct {
	addr netip.Addr
}

func (i *packetInfo) OOB() []byte { return nil }

// Stubs for non-OOB platforms. writeConnected in send_conn.go references these
// but is never called here (connectSharedSocket is a no-op on non-Darwin).
func appendIPv4ECNMsg(b []byte, _ protocol.ECN) []byte { return b }
func appendIPv6ECNMsg(b []byte, _ protocol.ECN) []byte { return b }
