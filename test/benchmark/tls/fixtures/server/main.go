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
	"strings"
	"syscall"
	"time"
)

const benchmarkTokenHeader = "X-Ecapture-Benchmark"

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:0", "address to listen on")
	readyFile := flag.String("ready-file", "", "file that receives the selected listen address")
	flag.Parse()

	if *readyFile == "" {
		log.Fatal("--ready-file is required")
	}
	certificate, err := selfSignedCertificate()
	if err != nil {
		log.Fatalf("generate certificate: %v", err)
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/upload", func(writer http.ResponseWriter, request *http.Request) {
		requestToken := request.Header.Get(benchmarkTokenHeader)
		if request.Method != http.MethodPost || !strings.Contains(requestToken, "_REQ_") {
			http.Error(writer, "invalid benchmark request", http.StatusBadRequest)
			return
		}
		bodyBytes, err := io.Copy(io.Discard, request.Body)
		if err != nil || bodyBytes != request.ContentLength {
			http.Error(writer, "incomplete benchmark upload", http.StatusBadRequest)
			return
		}

		responseToken := strings.Replace(requestToken, "_REQ_", "_RESP_", 1)
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Connection", "close")
		_, _ = fmt.Fprintln(writer, responseToken)
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	if err := os.WriteFile(*readyFile, []byte(listener.Addr().String()+"\n"), 0o600); err != nil {
		log.Fatalf("write ready file: %v", err)
	}
	log.Printf("TLS benchmark fixture listening on %s", listener.Addr())

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
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "eCapture benchmark"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
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
