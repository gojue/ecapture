// File: test/e2e/go_https_client.go
// Simple HTTPS client for testing GoTLS capture

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "https://github.com/", "URL to request")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	dnsServer := flag.String("dns", "", "Custom DNS server (e.g. 8.8.8.8:53). Overrides system resolver.")
	tlsVersion := flag.String("tls-version", "default", "TLS version: default, 1.2, or 1.3")
	expect := flag.String("expect", "", "Fail unless the response body contains this text")
	flag.Parse()

	var minVersion uint16
	var maxVersion uint16
	switch *tlsVersion {
	case "default":
	case "1.2":
		minVersion = tls.VersionTLS12
		maxVersion = tls.VersionTLS12
	case "1.3":
		minVersion = tls.VersionTLS13
		maxVersion = tls.VersionTLS13
	default:
		fmt.Fprintf(os.Stderr, "Unsupported TLS version: %s\n", *tlsVersion)
		os.Exit(2)
	}

	// Build a custom dialer that uses an explicit DNS server when provided.
	// This is necessary on Android emulators where /etc/resolv.conf may point
	// to [::1]:53 (IPv6 loopback) which is not listening, causing DNS failures.
	dialContext := (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}).DialContext

	if *dnsServer != "" {
		addr := *dnsServer
		// Ensure port is included
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", addr)
			},
		}
		dialContext = (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
			Resolver:  resolver,
		}).DialContext
		log.Printf("Using custom DNS server: %s", addr)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: dialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecure,
				MinVersion:         minVersion,
				MaxVersion:         maxVersion,
			},
		},
	}

	log.Printf("Making HTTPS request to %s", *url)
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	log.Printf("Response status: %s", resp.Status)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response body: %v\n", err)
		os.Exit(1)
	}
	if *expect != "" && !strings.Contains(string(body), *expect) {
		fmt.Fprintf(os.Stderr, "Response body does not contain expected text: %s\n", *expect)
		os.Exit(1)
	}

	fmt.Printf("Response body (%d bytes):\n%s\n", len(body), string(body))
}
