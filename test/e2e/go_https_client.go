// File: test/e2e/go_https_client.go
// Simple HTTPS client for testing GoTLS capture

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	url := flag.String("url", "https://127.0.0.1:8445/", "URL to request")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	flag.Parse()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
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
