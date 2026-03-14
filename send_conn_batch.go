//go:build darwin || linux || freebsd || windows

package quic

import (
	"net"

	"golang.org/x/net/ipv4"

	"github.com/quic-go/quic-go/internal/protocol"
)

// WriteBatch writes multiple packets in a single batched syscall when the
// underlying connection supports it (sendmsg_x on macOS, sendmmsg on Linux).
// Returns the number of messages successfully sent.
func (c *sconn) WriteBatch(entries []queueEntry) (int, error) {
	// Connected path: nil addr (msg_name=NULL) → XNU pru_sosend_list fast path.
	if c.isConnected {
		return c.writeBatchConnected(entries)
	}

	oobC, ok := c.rawConn.(*oobConn)
	if !ok {
		return c.writeBatchIndividual(entries)
	}
	type batchWriter interface {
		WriteBatch(ms []ipv4.Message, flags int) (int, error)
	}
	bw, ok := oobC.batchConn.(batchWriter)
	if !ok {
		return c.writeBatchIndividual(entries)
	}

	ai := c.remoteAddrInfo.Load()
	msgs := make([]ipv4.Message, len(entries))
	for i, e := range entries {
		oob := buildWriteOOB(ai.oob, oobC, ai.addr, e.gsoSize, e.ecn)
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{e.buf.Data},
			Addr:    ai.addr,
			OOB:     oob,
		}
	}
	return bw.WriteBatch(msgs, 0)
}

// writeBatchConnected sends via the connected shared socket with Addr=nil.
// Uses c.batchWriter (raw sendmsg_x) for XNU's pru_sosend_list fast path.
func (c *sconn) writeBatchConnected(entries []queueEntry) (int, error) {
	ecnEnabled := c.rawConn.capabilities().ECN
	msgs := make([]ipv4.Message, len(entries))
	for i, e := range entries {
		var oob []byte
		if e.ecn != protocol.ECNUnsupported && ecnEnabled {
			if c.isIPv4 {
				oob = appendIPv4ECNMsg(nil, e.ecn)
			} else {
				oob = appendIPv6ECNMsg(nil, e.ecn)
			}
		}
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{e.buf.Data},
			OOB:     oob,
		}
	}
	return c.batchWriter.WriteBatch(msgs, 0)
}

// buildWriteOOB constructs the OOB control data for a single outgoing packet,
// including packet info, GSO segment size, and ECN bits.
func buildWriteOOB(baseOOB []byte, oobC *oobConn, addr net.Addr, gsoSize uint16, ecn protocol.ECN) []byte {
	oob := make([]byte, len(baseOOB), len(baseOOB)+64)
	copy(oob, baseOOB)
	if gsoSize > 0 && oobC.capabilities().GSO {
		oob = appendUDPSegmentSizeMsg(oob, gsoSize)
	}
	if ecn != protocol.ECNUnsupported && oobC.capabilities().ECN {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			if udpAddr.IP.To4() != nil {
				oob = appendIPv4ECNMsg(oob, ecn)
			} else {
				oob = appendIPv6ECNMsg(oob, ecn)
			}
		}
	}
	return oob
}

func (c *sconn) writeBatchIndividual(entries []queueEntry) (int, error) {
	for i, e := range entries {
		if err := c.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
			return i, err
		}
	}
	return len(entries), nil
}
