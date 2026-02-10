//go:build darwin

package quic

import (
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

func TestMsghdrXSize(t *testing.T) {
	// msghdr_x on arm64/amd64 Darwin must be exactly 56 bytes.
	require.Equal(t, uintptr(56), unsafe.Sizeof(msghdrX{}))
}

func TestBatchReadSingle(t *testing.T) {
	// Set up a UDP socket pair.
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := net.ListenUDP("udp4", laddr)
	require.NoError(t, err)
	defer conn.Close()

	bc, err := newDarwinBatchConn(conn)
	require.NoError(t, err)

	// Send a single packet to ourselves.
	payload := []byte("hello batch read")
	_, err = conn.WriteToUDP(payload, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	// Read it back via ReadBatch.
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 1500)}
		msgs[i].OOB = make([]byte, 128)
	}

	n, err := bc.ReadBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, len(payload), msgs[0].N)
	require.Equal(t, payload, msgs[0].Buffers[0][:msgs[0].N])
}

func TestBatchReadMultiple(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := net.ListenUDP("udp4", laddr)
	require.NoError(t, err)
	defer conn.Close()

	bc, err := newDarwinBatchConn(conn)
	require.NoError(t, err)

	// Send 16 packets.
	const numPackets = 16
	for i := 0; i < numPackets; i++ {
		payload := []byte{byte(i)}
		_, err = conn.WriteToUDP(payload, conn.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
	}

	// Read them back — may take multiple ReadBatch calls due to timing.
	msgs := make([]ipv4.Message, batchSize)
	var totalRead int
	for totalRead < numPackets {
		for i := range msgs {
			msgs[i].Buffers = [][]byte{make([]byte, 1500)}
			msgs[i].OOB = make([]byte, 128)
		}
		n, err := bc.ReadBatch(msgs, 0)
		require.NoError(t, err)
		require.Greater(t, n, 0, "ReadBatch should return at least 1 packet")
		for i := 0; i < n; i++ {
			require.Equal(t, 1, msgs[i].N)
			require.Equal(t, byte(totalRead+i), msgs[i].Buffers[0][0])
		}
		totalRead += n
	}
	require.Equal(t, numPackets, totalRead)
}

func TestBatchWriteMultiple(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := net.ListenUDP("udp4", laddr)
	require.NoError(t, err)
	defer conn.Close()

	bc, err := newDarwinBatchConn(conn)
	require.NoError(t, err)

	dst := conn.LocalAddr().(*net.UDPAddr)

	// Build batch of 16 messages.
	const numPackets = 16
	msgs := make([]ipv4.Message, numPackets)
	for i := range msgs {
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{{byte(i), byte(i + 1)}},
			Addr:    dst,
		}
	}

	nsent, err := bc.WriteBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, numPackets, nsent)

	// Read them back individually.
	buf := make([]byte, 1500)
	for i := 0; i < numPackets; i++ {
		n, _, err := conn.ReadFromUDP(buf)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		require.Equal(t, byte(i), buf[0])
		require.Equal(t, byte(i+1), buf[1])
	}
}

func TestBatchSockaddrIPv4Roundtrip(t *testing.T) {
	orig := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 42), Port: 12345}
	var buf [unix.SizeofSockaddrInet6]byte
	n := marshalSockaddr(orig, buf[:], false)
	require.Equal(t, unix.SizeofSockaddrInet4, n)

	addr, err := parseSockaddr(buf[:n])
	require.NoError(t, err)
	parsed := addr.(*net.UDPAddr)
	require.True(t, orig.IP.Equal(parsed.IP), "IP mismatch: %v vs %v", orig.IP, parsed.IP)
	require.Equal(t, orig.Port, parsed.Port)
}

func TestBatchWriteWithECN(t *testing.T) {
	// Reproduce EINVAL: test sendmsg_x with ECN control messages (OOB).
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	bc, err := newDarwinBatchConn(conn)
	require.NoError(t, err)

	dst := conn.LocalAddr().(*net.UDPAddr)

	// Build OOB with ECN bits (same as QUIC does).
	oob := appendIPv4ECNMsg(nil, 0x02) // ECT(0)

	msgs := []ipv4.Message{
		{
			Buffers: [][]byte{[]byte("ecn test packet")},
			Addr:    dst,
			OOB:     oob,
		},
	}

	nsent, err := bc.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch with ECN OOB failed")
	require.Equal(t, 1, nsent)
}

func TestBatchWriteWithPacketInfo(t *testing.T) {
	// Test sendmsg_x with packetInfo OOB (like QUIC connections bound to 0.0.0.0).
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	bc, err := newDarwinBatchConn(conn)
	require.NoError(t, err)

	dst := conn.LocalAddr().(*net.UDPAddr)

	// Test with empty OOB (no control messages).
	msgs := []ipv4.Message{
		{
			Buffers: [][]byte{[]byte("no oob")},
			Addr:    dst,
			OOB:     nil,
		},
	}
	nsent, err := bc.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch with nil OOB failed")
	require.Equal(t, 1, nsent)

	// Test with empty but non-nil OOB.
	msgs[0].OOB = []byte{}
	msgs[0].Buffers[0] = []byte("empty oob")
	nsent, err = bc.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch with empty OOB failed")
	require.Equal(t, 1, nsent)
}

func TestBatchWriteMultipleWithECN(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	bc, err := newDarwinBatchConn(conn)
	require.NoError(t, err)

	dst := conn.LocalAddr().(*net.UDPAddr)

	// Build batch of 16 messages, each with ECN OOB.
	const numPackets = 16
	msgs := make([]ipv4.Message, numPackets)
	for i := range msgs {
		oob := appendIPv4ECNMsg(nil, 0x02)
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{{byte(i)}},
			Addr:    dst,
			OOB:     oob,
		}
	}

	nsent, err := bc.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch with 16 ECN messages failed")
	require.Equal(t, numPackets, nsent)
}

func TestBatchWriteBetweenSockets(t *testing.T) {
	// Two different sockets, like QUIC client→server.
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sender.Close()

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer receiver.Close()

	bc, err := newDarwinBatchConn(sender)
	require.NoError(t, err)

	dst := receiver.LocalAddr().(*net.UDPAddr)

	// Enable IP_RECVTOS on sender to match QUIC setup (oobConn does this).
	rawConn, err := sender.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rawConn.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
	}))

	// Send 8 messages with ECN OOB to a different socket.
	const numPackets = 8
	msgs := make([]ipv4.Message, numPackets)
	for i := range msgs {
		oob := appendIPv4ECNMsg(nil, 0x02)
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{make([]byte, 1200)},
			Addr:    dst,
			OOB:     oob,
		}
		msgs[i].Buffers[0][0] = byte(i)
	}

	nsent, err := bc.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch between sockets failed")
	require.Equal(t, numPackets, nsent)

	// Verify all packets arrived.
	buf := make([]byte, 1500)
	for i := 0; i < numPackets; i++ {
		n, _, err := receiver.ReadFromUDP(buf)
		require.NoError(t, err)
		require.Equal(t, 1200, n)
		require.Equal(t, byte(i), buf[0])
	}
}

func TestBatchWriteViaOobConn(t *testing.T) {
	// Reproduce the exact QUIC path: create oobConn, then WriteBatch via its batchConn.
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sender.Close()

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer receiver.Close()

	// Create oobConn like QUIC does (this sets socket options AND creates darwinBatchConn).
	oobC, err := newConn(sender, false)
	require.NoError(t, err)

	// Get the batchWriter from oobConn.
	type batchWriter interface {
		WriteBatch(ms []ipv4.Message, flags int) (int, error)
	}
	bw, ok := oobC.batchConn.(batchWriter)
	require.True(t, ok, "batchConn should support WriteBatch")

	dst := receiver.LocalAddr().(*net.UDPAddr)

	// Build ECN OOB (same as buildWriteOOB produces).
	oob := appendIPv4ECNMsg(nil, 0x02)
	t.Logf("OOB len: %d", len(oob))

	const numPackets = 4
	msgs := make([]ipv4.Message, numPackets)
	for i := range msgs {
		data := make([]byte, 1280)
		data[0] = byte(i)
		msgs[i] = ipv4.Message{
			Buffers: [][]byte{data},
			Addr:    dst,
			OOB:     oob,
		}
	}

	nsent, err := bw.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch via oobConn's batchConn failed")
	require.Equal(t, numPackets, nsent)
}

func TestBatchWriteDualStackSocket(t *testing.T) {
	// Reproduce the QUIC client path: dual-stack socket ("udp" + IPv4zero).
	// This creates an IPv6 socket that accepts IPv4 via mapped addresses.
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	defer sender.Close()
	t.Logf("sender local addr: %v (%T)", sender.LocalAddr(), sender.LocalAddr())

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer receiver.Close()

	bc, err := newDarwinBatchConn(sender)
	require.NoError(t, err)

	dst := receiver.LocalAddr().(*net.UDPAddr)
	t.Logf("sending to: %v", dst)

	msgs := []ipv4.Message{
		{
			Buffers: [][]byte{[]byte("dual stack test")},
			Addr:    dst,
		},
	}

	nsent, err := bc.WriteBatch(msgs, 0)
	require.NoError(t, err, "WriteBatch on dual-stack socket to IPv4 addr failed")
	require.Equal(t, 1, nsent)
}

func TestBatchSockaddrIPv4MappedRoundtrip(t *testing.T) {
	// Test IPv4 address marshaled as IPv4-mapped IPv6 (forceIPv6=true).
	orig := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 42), Port: 12345}
	var buf [unix.SizeofSockaddrInet6]byte
	n := marshalSockaddr(orig, buf[:], true)
	require.Equal(t, unix.SizeofSockaddrInet6, n)
	require.Equal(t, byte(syscall.AF_INET6), buf[1], "should be AF_INET6")

	addr, err := parseSockaddr(buf[:n])
	require.NoError(t, err)
	parsed := addr.(*net.UDPAddr)
	require.True(t, orig.IP.Equal(parsed.IP), "IP mismatch: %v vs %v", orig.IP, parsed.IP)
	require.Equal(t, orig.Port, parsed.Port)
}

func TestBatchSockaddrIPv6Roundtrip(t *testing.T) {
	orig := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 54321}
	var buf [unix.SizeofSockaddrInet6]byte
	n := marshalSockaddr(orig, buf[:], false)
	require.Equal(t, unix.SizeofSockaddrInet6, n)

	addr, err := parseSockaddr(buf[:n])
	require.NoError(t, err)
	parsed := addr.(*net.UDPAddr)
	require.True(t, orig.IP.Equal(parsed.IP), "IP mismatch: %v vs %v", orig.IP, parsed.IP)
	require.Equal(t, orig.Port, parsed.Port)
}

// TestConnectedVsUnconnectedThroughput compares sendmsg_x throughput with:
// 1. Unconnected socket + msg_name + msg_control (current QUIC path — XNU falls back to per-message sendit)
// 2. Connected socket + msg_name=NULL + msg_control=NULL (proposed — should hit XNU's pru_sosend_list)
// 3. Individual sendmsg as baseline
func TestConnectedVsUnconnectedThroughput(t *testing.T) {
	const (
		packetSize  = 1200 // typical QUIC packet
		numPackets  = 16   // batch size
		numBatches  = 50000
		totalPkts   = numBatches * numPackets
	)

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer receiver.Close()

	// Increase receiver buffer so we don't drop packets.
	receiver.SetReadBuffer(16 * 1024 * 1024)

	dst := receiver.LocalAddr().(*net.UDPAddr)
	payload := make([]byte, packetSize)

	// --- Test 1: Unconnected + msg_name + msg_control (current QUIC path) ---
	t.Run("unconnected_with_addr_and_oob", func(t *testing.T) {
		sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer sender.Close()
		sender.SetWriteBuffer(16 * 1024 * 1024)

		bc, err := newDarwinBatchConn(sender)
		require.NoError(t, err)

		oob := appendIPv4ECNMsg(nil, 0x02) // ECT(0)

		msgs := make([]ipv4.Message, numPackets)
		for i := range msgs {
			msgs[i] = ipv4.Message{
				Buffers: [][]byte{payload},
				Addr:    dst,
				OOB:     oob,
			}
		}

		start := time.Now()
		for b := 0; b < numBatches; b++ {
			n, err := bc.WriteBatch(msgs, 0)
			if err != nil {
				t.Fatalf("batch %d: %v", b, err)
			}
			if n != numPackets {
				t.Fatalf("batch %d: sent %d/%d", b, n, numPackets)
			}
		}
		elapsed := time.Since(start)

		bytes := int64(totalPkts) * int64(packetSize)
		t.Logf("Unconnected+addr+OOB: %d packets in %v (%.2f Mpps, %.2f MB/s)",
			totalPkts, elapsed,
			float64(totalPkts)/elapsed.Seconds()/1e6,
			float64(bytes)/elapsed.Seconds()/1e6)
	})

	// --- Test 2: Connected + NO msg_name + NO msg_control (proposed fast path) ---
	t.Run("connected_no_addr_no_oob", func(t *testing.T) {
		sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer sender.Close()
		sender.SetWriteBuffer(16 * 1024 * 1024)

		// Connect the UDP socket to the receiver — makes it a "connected UDP socket".
		rawConn, err := sender.SyscallConn()
		require.NoError(t, err)
		var connectErr error
		err = rawConn.Control(func(fd uintptr) {
			// Set ECN at socket level instead of per-packet OOB.
			unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 0x02) // ECT(0)

			// connect() the UDP socket.
			sa := &unix.SockaddrInet4{Port: dst.Port}
			copy(sa.Addr[:], dst.IP.To4())
			connectErr = unix.Connect(int(fd), sa)
		})
		require.NoError(t, err)
		require.NoError(t, connectErr, "connect() on UDP socket failed")

		bc, err := newDarwinBatchConn(sender)
		require.NoError(t, err)

		// Messages with NO addr and NO OOB — should hit pru_sosend_list.
		msgs := make([]ipv4.Message, numPackets)
		for i := range msgs {
			msgs[i] = ipv4.Message{
				Buffers: [][]byte{payload},
				Addr:    nil,
				OOB:     nil,
			}
		}

		start := time.Now()
		for b := 0; b < numBatches; b++ {
			n, err := bc.WriteBatch(msgs, 0)
			if err != nil {
				t.Fatalf("batch %d: %v", b, err)
			}
			if n != numPackets {
				t.Fatalf("batch %d: sent %d/%d", b, n, numPackets)
			}
		}
		elapsed := time.Since(start)

		bytes := int64(totalPkts) * int64(packetSize)
		t.Logf("Connected+no_addr+no_OOB: %d packets in %v (%.2f Mpps, %.2f MB/s)",
			totalPkts, elapsed,
			float64(totalPkts)/elapsed.Seconds()/1e6,
			float64(bytes)/elapsed.Seconds()/1e6)
	})

	// --- Test 3: Individual sendmsg (baseline — no batching at all) ---
	t.Run("individual_sendmsg", func(t *testing.T) {
		sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer sender.Close()
		sender.SetWriteBuffer(16 * 1024 * 1024)

		start := time.Now()
		for i := 0; i < totalPkts; i++ {
			_, err := sender.WriteToUDP(payload, dst)
			if err != nil {
				t.Fatalf("packet %d: %v", i, err)
			}
		}
		elapsed := time.Since(start)

		bytes := int64(totalPkts) * int64(packetSize)
		t.Logf("Individual sendmsg: %d packets in %v (%.2f Mpps, %.2f MB/s)",
			totalPkts, elapsed,
			float64(totalPkts)/elapsed.Seconds()/1e6,
			float64(bytes)/elapsed.Seconds()/1e6)
	})

	// --- Test 4: Connected + NO msg_name + WITH msg_control (to isolate msg_name vs msg_control) ---
	t.Run("connected_no_addr_with_oob", func(t *testing.T) {
		sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer sender.Close()
		sender.SetWriteBuffer(16 * 1024 * 1024)

		rawConn, err := sender.SyscallConn()
		require.NoError(t, err)
		var connectErr error
		err = rawConn.Control(func(fd uintptr) {
			sa := &unix.SockaddrInet4{Port: dst.Port}
			copy(sa.Addr[:], dst.IP.To4())
			connectErr = unix.Connect(int(fd), sa)
		})
		require.NoError(t, err)
		require.NoError(t, connectErr)

		bc, err := newDarwinBatchConn(sender)
		require.NoError(t, err)

		oob := appendIPv4ECNMsg(nil, 0x02)

		msgs := make([]ipv4.Message, numPackets)
		for i := range msgs {
			msgs[i] = ipv4.Message{
				Buffers: [][]byte{payload},
				Addr:    nil,
				OOB:     oob,
			}
		}

		start := time.Now()
		for b := 0; b < numBatches; b++ {
			n, err := bc.WriteBatch(msgs, 0)
			if err != nil {
				t.Fatalf("batch %d: %v", b, err)
			}
			if n != numPackets {
				t.Fatalf("batch %d: sent %d/%d", b, n, numPackets)
			}
		}
		elapsed := time.Since(start)

		bytes := int64(totalPkts) * int64(packetSize)
		t.Logf("Connected+no_addr+WITH_OOB: %d packets in %v (%.2f Mpps, %.2f MB/s)",
			totalPkts, elapsed,
			float64(totalPkts)/elapsed.Seconds()/1e6,
			float64(bytes)/elapsed.Seconds()/1e6)
	})
}
