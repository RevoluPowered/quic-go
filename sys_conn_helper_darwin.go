//go:build darwin

package quic

import (
	"encoding/binary"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	msgTypeIPTOS = unix.IP_RECVTOS
	ipv4PKTINFO  = unix.IP_RECVPKTINFO
)

const ecnIPv4DataLen = 4

// batchSize is the number of packets to read/write in a single syscall.
// We use sendmsg_x/recvmsg_x on Darwin which support batched I/O,
// so we can batch more than Linux's recvmmsg (which uses 8).
const batchSize = 16

func parseIPv4PktInfo(body []byte) (ip netip.Addr, ifIndex uint32, ok bool) {
	// struct in_pktinfo {
	// 	unsigned int   ipi_ifindex;  /* Interface index */
	// 	struct in_addr ipi_spec_dst; /* Local address */
	// 	struct in_addr ipi_addr;     /* Header Destination address */
	// };
	if len(body) != 12 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(*(*[4]byte)(body[8:12])), binary.NativeEndian.Uint32(body), true
}

func isGSOEnabled(syscall.RawConn) bool { return false }

func isECNEnabled() bool { return !isECNDisabledUsingEnv() }
