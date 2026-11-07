// Command http3 provides deterministic QUIC v1/v2 traffic without an application
// keylog writer. Every capture secret must be obtained by eCapture's GoTLS probe.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	mode := flag.String("mode", "client", "server or client")
	address := flag.String("address", "127.0.0.1:0", "loopback UDP listen or server address")
	readyFile := flag.String("ready-file", "", "server readiness file")
	token := flag.String("token", "ECAPTURE_E2E_HTTP3", "body marker prefix")
	quicVersion := flag.String("quic-version", "v1", "QUIC version: v1 or v2")
	flag.Parse()

	var version quic.Version
	switch *quicVersion {
	case "v1":
		version = quic.Version1
	case "v2":
		version = quic.Version2
	default:
		log.Fatalf("unsupported QUIC version %q (want v1 or v2)", *quicVersion)
	}

	var err error
	switch *mode {
	case "server":
		err = serve(*address, *readyFile, *token, version)
	case "client":
		err = request(*address, *token, version)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(address, readyFile, token string, version quic.Version) error {
	if readyFile == "" {
		return fmt.Errorf("--ready-file is required")
	}
	cert, err := certificate()
	if err != nil {
		return err
	}
	listener, err := net.ListenPacket("udp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	var firstMu sync.Mutex
	var firstPeers [2]string
	firstRequests := make(chan struct{})
	server := &http3.Server{
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{cert}},
		QUICConfig: &quic.Config{Versions: []quic.Version{version}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			connection, connErr := strconv.Atoi(r.URL.Query().Get("connection"))
			stream, streamErr := strconv.Atoi(r.URL.Query().Get("stream"))
			if r.Method != http.MethodPost || r.ProtoMajor != 3 || connErr != nil || streamErr != nil ||
				connection < 0 || connection > 1 || (stream != 0 && stream != 4) {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err != nil || string(body) != marker(token, connection, stream, "REQUEST") {
				http.Error(w, "request body mismatch", http.StatusBadRequest)
				return
			}
			if stream == 0 {
				// Neither connection can finish its first exchange until both
				// distinct QUIC peers have sent their first request.
				firstMu.Lock()
				if firstPeers[connection] != "" || firstPeers[1-connection] == r.RemoteAddr {
					firstMu.Unlock()
					http.Error(w, "expected two distinct connections", http.StatusBadRequest)
					return
				}
				firstPeers[connection] = r.RemoteAddr
				if firstPeers[0] != "" && firstPeers[1] != "" {
					close(firstRequests)
				}
				firstMu.Unlock()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-firstRequests:
				case <-timer.C:
					http.Error(w, "concurrent connection barrier timed out", http.StatusGatewayTimeout)
					return
				case <-r.Context().Done():
					return
				}
			}
			response := marker(token, connection, stream, "RESPONSE")
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(len(response)))
			_, _ = io.WriteString(w, response)
		}),
	}
	defer server.Close()
	if err := os.WriteFile(readyFile, []byte(listener.LocalAddr().String()+"\n"), 0o600); err != nil {
		return err
	}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdown)
	go func() {
		<-shutdown
		_ = server.Close()
	}()
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func request(address, token string, version quic.Version) error {
	results := make(chan error, 2)
	for connection := 0; connection < 2; connection++ {
		go func(connection int) { results <- requestConnection(address, token, connection, version) }(connection)
	}
	return errors.Join(<-results, <-results)
}

func requestConnection(address, token string, connection int, version quic.Version) error {
	// Each concurrent worker owns a transport and QUIC connection. Sequential
	// requests within that connection retain deterministic stream IDs 0 and 4.
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, // Ephemeral loopback certificate.
		QUICConfig:      &quic.Config{Versions: []quic.Version{version}},
	}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for _, stream := range []int{0, 4} {
		target := fmt.Sprintf("https://%s/e2e?connection=%d&stream=%d", address, connection, stream)
		response, err := client.Post(target, "text/plain", strings.NewReader(marker(token, connection, stream, "REQUEST")))
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if readErr != nil || response.ProtoMajor != 3 || response.StatusCode != http.StatusOK ||
			!bytes.Equal(body, []byte(marker(token, connection, stream, "RESPONSE"))) {
			return fmt.Errorf("HTTP/3 connection %d stream %d response mismatch", connection, stream)
		}
	}
	return nil
}

func marker(token string, connection, stream int, direction string) string {
	return fmt.Sprintf("%s_C%d_S%d_%s\n", token, connection, stream, direction)
}

func certificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "eCapture E2E"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
