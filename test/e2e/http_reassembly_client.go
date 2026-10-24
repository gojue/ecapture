// File: test/e2e/http_reassembly_client.go
// Deterministic TLS client for the eCapture E2E "multi-PSH body reassembly"
// cases. It sends a POST body built from several chunks and verifies the
// server echoes it back verbatim.
//
// HTTP/1.1 mode writes the request body with multiple Write calls (and
// TCP_NODELAY) so the body reaches eCapture as multiple TCP PSH segments.
// HTTP/2 mode issues --requests POSTs over a single reused connection
// (keep-alive) and therefore exercises HTTP/2 stream multiplexing.

package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	rawURL := flag.String("url", "", "server URL, e.g. https://127.0.0.1:PORT/echo")
	insecure := flag.Bool("insecure", false, "skip TLS verification")
	enableH2 := flag.Bool("h2", false, "use HTTP/2 (keep-alive) instead of raw HTTP/1.1")
	tlsVersion := flag.String("tls-version", "default", "TLS version: default, 1.2, or 1.3")
	token := flag.String("token", "ECAPTURE_E2E_OK", "chunk marker token")
	chunkSize := flag.Int("chunk-size", 16384, "padding bytes per body chunk")
	chunkCount := flag.Int("chunk-count", 8, "number of body chunks")
	chunkDelay := flag.Duration("chunk-delay", 0, "delay between chunk writes")
	requests := flag.Int("requests", 1, "number of sequential requests (HTTP/2 keep-alive)")
	outRequestBody := flag.String("out-request-body", "", "write the request body to this file")
	flag.Parse()

	if *rawURL == "" || *token == "" {
		log.Fatal("--url and --token are required")
	}
	if *chunkSize < 1 || *chunkCount < 1 || *requests < 1 {
		log.Fatal("--chunk-size, --chunk-count, and --requests must be positive")
	}

	chunks := buildChunks(*token, *chunkCount, *chunkSize)
	body := bytes.Join(chunks, nil)
	if *outRequestBody != "" {
		if err := os.WriteFile(*outRequestBody, body, 0o600); err != nil {
			log.Fatalf("write request body: %v", err)
		}
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: *insecure}
	switch *tlsVersion {
	case "default":
	case "1.2":
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	case "1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	default:
		log.Fatalf("unsupported TLS version: %s", *tlsVersion)
	}

	var err error
	if *enableH2 {
		tlsConfig.NextProtos = []string{"h2"}
		err = runHTTP2(*rawURL, tlsConfig, body, *requests)
	} else {
		tlsConfig.NextProtos = []string{"http/1.1"}
		err = runHTTP1Raw(*rawURL, tlsConfig, body, chunks, *chunkDelay)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
}

// buildChunks returns one logical body chunk per element. Every chunk begins
// with a unique "<token>_CHUNK_<i>" marker line followed by padding, matching
// the format produced by the http_reassembly_server fixture.
func buildChunks(token string, chunkCount, chunkSize int) [][]byte {
	chunks := make([][]byte, chunkCount)
	for i := 0; i < chunkCount; i++ {
		chunks[i] = make([]byte, 0, len(token)+32+chunkSize)
		chunks[i] = append(chunks[i], fmt.Sprintf("%s_CHUNK_%d\n", token, i)...)
		pad := byte('a' + i%26)
		for j := 0; j < chunkSize; j++ {
			chunks[i] = append(chunks[i], pad)
		}
		chunks[i] = append(chunks[i], '\n')
	}
	return chunks
}

// runHTTP1Raw sends one HTTP/1.1 POST with the body written as separate
// Write calls, then validates that the response echoes the body verbatim.
func runHTTP1Raw(rawURL string, tlsConfig *tls.Config, body []byte, chunks [][]byte, chunkDelay time.Duration) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}

	conn, err := net.DialTimeout("tcp", u.Host, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// Push each Write immediately so the body spans multiple PSH segments.
		_ = tcpConn.SetNoDelay(true)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()

	var header bytes.Buffer
	fmt.Fprintf(&header, "POST %s HTTP/1.1\r\n", u.RequestURI())
	fmt.Fprintf(&header, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&header, "Content-Type: application/octet-stream\r\n")
	fmt.Fprintf(&header, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&header, "Connection: close\r\n\r\n")

	if _, err := tlsConn.Write(header.Bytes()); err != nil {
		return fmt.Errorf("write request headers: %w", err)
	}
	for i, chunk := range chunks {
		if _, err := tlsConn.Write(chunk); err != nil {
			return fmt.Errorf("write body chunk %d: %w", i, err)
		}
		if chunkDelay > 0 {
			time.Sleep(chunkDelay)
		}
	}

	rawResponse, err := io.ReadAll(tlsConn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if err := validateEchoedBody(rawResponse, body); err != nil {
		return err
	}
	log.Printf("HTTP/1.1 response echoes %d-byte body", len(body))
	return nil
}

// runHTTP2 sends several POSTs over one reused HTTP/2 connection and verifies
// that every response echoes the request body verbatim.
func runHTTP2(rawURL string, tlsConfig *tls.Config, body []byte, requestCount int) error {
	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	defer transport.CloseIdleConnections()

	for i := 0; i < requestCount; i++ {
		target := rawURL
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		target = fmt.Sprintf("%s%sreq=%d", target, sep, i)

		request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request %d: %w", i, err)
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		request.ContentLength = int64(len(body))

		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("request %d: %w", i, err)
		}
		responseBody, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read response %d: %w", i, readErr)
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("request %d: unexpected status %s", i, response.Status)
		}
		if !bytes.Equal(responseBody, body) {
			return fmt.Errorf("request %d: echoed body mismatch (got %d bytes, want %d)", i, len(responseBody), len(body))
		}
		log.Printf("HTTP/2 request %d echoes %d-byte body", i, len(body))
	}
	return nil
}

// validateEchoedBody confirms that a raw HTTP/1.1 response body equals body.
func validateEchoedBody(rawResponse, body []byte) error {
	headerEnd := bytes.Index(rawResponse, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return fmt.Errorf("response has no header/body separator")
	}
	responseBody := rawResponse[headerEnd+4:]
	if !bytes.Equal(responseBody, body) {
		return fmt.Errorf("echoed body mismatch (got %d bytes, want %d)", len(responseBody), len(body))
	}
	return nil
}
