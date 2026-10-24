// Command http_reassembly_server is a deterministic TLS fixture for the
// eCapture E2E tests that verify the pcapng text-source reassembles an HTTP
// body that spans multiple TCP segments (PSH packets).
//
// It serves HTTP/1.1 and, with --h2, HTTP/2 over a single TLS listener. Two
// endpoints are provided:
//
//   - /echo reads the request body and returns it verbatim, so the client and
//     the eCapture output can both be compared against the original request.
//   - /chunked returns a deterministic body written as multiple chunks, each
//     flushed to the wire separately to force multiple TCP PSH segments.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:0", "address to listen on")
	readyFile := flag.String("ready-file", "", "file that receives the selected listen address")
	token := flag.String("token", "ECAPTURE_E2E_OK", "chunk marker token")
	enableH2 := flag.Bool("h2", false, "enable HTTP/2 alongside HTTP/1.1")
	chunkSize := flag.Int("chunk-size", 16384, "padding bytes per body chunk")
	chunkCount := flag.Int("chunk-count", 8, "number of body chunks")
	chunkDelay := flag.Duration("chunk-delay", 0, "delay between chunk writes")
	flag.Parse()

	if *readyFile == "" {
		log.Fatal("--ready-file is required")
	}
	if *chunkSize < 1 || *chunkCount < 1 {
		log.Fatal("--chunk-size and --chunk-count must be positive")
	}

	certificate, err := selfSignedCertificate()
	if err != nil {
		log.Fatalf("generate certificate: %v", err)
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	if *enableH2 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Ecapture-E2E", *token)
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	})

	mux.HandleFunc("/chunked", func(writer http.ResponseWriter, request *http.Request) {
		// Write each chunk with a dedicated Write+Flush so the body reaches the
		// client (and eCapture) as multiple TCP PSH segments.
		total := chunkBodySize(*token, *chunkCount, *chunkSize)
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Ecapture-E2E", *token)
		writer.Header().Set("Content-Length", strconv.Itoa(total))
		writer.WriteHeader(http.StatusOK)
		flusher, _ := writer.(http.Flusher)
		for i := 0; i < *chunkCount; i++ {
			if _, err := writer.Write(chunkBytes(*token, i, *chunkSize)); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			if *chunkDelay > 0 {
				time.Sleep(*chunkDelay)
			}
		}
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if *enableH2 {
		if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
			log.Fatalf("configure HTTP/2: %v", err)
		}
	}

	tlsListener := tls.NewListener(listener, tlsConfig)
	if err := os.WriteFile(*readyFile, []byte(listener.Addr().String()+"\n"), 0o600); err != nil {
		log.Fatalf("write ready file: %v", err)
	}
	log.Printf("HTTP reassembly TLS fixture listening on %s (h2=%v)", listener.Addr(), *enableH2)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}

// chunkBytes renders one logical body chunk. Every chunk starts with a unique
// marker line "<token>_CHUNK_<i>" followed by a padding line. The marker line
// is what the E2E assertions grep for to prove the body was reconstructed
// completely and in order.
func chunkBytes(token string, index, chunkSize int) []byte {
	out := make([]byte, 0, len(token)+32+chunkSize)
	out = append(out, fmt.Sprintf("%s_CHUNK_%d\n", token, index)...)
	pad := byte('a' + index%26)
	for i := 0; i < chunkSize; i++ {
		out = append(out, pad)
	}
	out = append(out, '\n')
	return out
}

// chunkBodySize reports the total body length for the given parameters so the
// server can advertise an accurate Content-Length.
func chunkBodySize(token string, chunkCount, chunkSize int) int {
	total := 0
	for i := 0; i < chunkCount; i++ {
		total += len(chunkBytes(token, i, chunkSize))
	}
	return total
}

func selfSignedCertificate() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "eCapture E2E"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
