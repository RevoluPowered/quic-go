package quic_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func generateBenchTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-bench"},
	}
}

func TestQUICStreamThroughput(t *testing.T) {
	tlsConf := generateBenchTLSConfig()
	quicConf := &quic.Config{MaxIdleTimeout: time.Minute}

	// Use explicit transports for clean shutdown (no stray goroutines).
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serverTr := &quic.Transport{Conn: serverConn}
	defer serverTr.Close()

	listener, err := serverTr.Listen(tlsConf, quicConf)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	totalBytes := int64(1_000_000_000) // 1GB
	chunkSize := 60000

	var wg sync.WaitGroup
	wg.Add(1)

	var serverElapsed time.Duration
	go func() {
		defer wg.Done()
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		buf := make([]byte, chunkSize)
		var total int64
		start := time.Now()
		for total < totalBytes {
			n, err := stream.Read(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		serverElapsed = time.Since(start)
	}()

	// Client: use DialAddr for single-use transport (triggers connectSharedSocket on Darwin).
	clientTLS := tlsConf.Clone()
	clientTLS.NextProtos = []string{"quic-bench"}
	conn, err := quic.DialAddr(context.Background(), listener.Addr().String(), clientTLS, quicConf)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, chunkSize)
	rand.Read(data)
	start := time.Now()
	for sent := int64(0); sent < totalBytes; sent += int64(chunkSize) {
		if _, err := stream.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	stream.Close()
	conn.CloseWithError(0, "")
	wg.Wait()
	clientElapsed := time.Since(start)

	// Wait for single-use client transport to fully shut down.
	// After conn.CloseWithError, the transport keeps closed-conn handlers briefly
	// (3*PTO) before removing them and stopping the listen goroutine.
	time.Sleep(500 * time.Millisecond)

	fmt.Printf("\nQUIC Stream Throughput (1GB loopback):\n")
	fmt.Printf("  Client write: %v (%.2f MB/s)\n", clientElapsed, float64(totalBytes)/clientElapsed.Seconds()/1e6)
	fmt.Printf("  Server read:  %v (%.2f MB/s)\n", serverElapsed, float64(totalBytes)/serverElapsed.Seconds()/1e6)
}
