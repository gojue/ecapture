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
	"time"
)

func main() {
	url := flag.String("url", "https://github.com/", "URL to request")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	dnsServer := flag.String("dns", "", "Custom DNS server (e.g. 8.8.8.8:53). Overrides system resolver.")
	flag.Parse()

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

	fmt.Printf("Response body (%d bytes):\n%s\n", len(body), string(body))
}
