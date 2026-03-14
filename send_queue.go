package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 16

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr) {
	h.conn.WriteTo(p.Data, addr)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			// Drain additional queued packets for batch sending.
			var entries [sendQueueCapacity]queueEntry
			entries[0] = e
			n := 1
		drain:
			for n < sendQueueCapacity {
				select {
				case e := <-h.queue:
					entries[n] = e
					n++
				default:
					break drain
				}
			}

			// Always try batch send (sendmsg_x with n=1 has same cost as sendmsg,
			// but keeps us on the connected-socket fast path on Darwin).
			if bsc, ok := h.conn.(interface {
				WriteBatch([]queueEntry) (int, error)
			}); ok {
				_, err := bsc.WriteBatch(entries[:n])
				for i := 0; i < n; i++ {
					entries[i].buf.Release()
				}
				if err != nil && !isSendMsgSizeErr(err) {
					return err
				}
				select {
				case h.available <- struct{}{}:
				default:
				}
				continue
			}

			// Fall back to individual sends (non-Darwin / no WriteBatch support).
			for i := 0; i < n; i++ {
				if err := h.conn.Write(entries[i].buf.Data, entries[i].gsoSize, entries[i].ecn); err != nil {
					if !isSendMsgSizeErr(err) {
						for j := i; j < n; j++ {
							entries[j].buf.Release()
						}
						return err
					}
				}
				entries[i].buf.Release()
			}
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
