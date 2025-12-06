// File: test/e2e/go_https_server.go
// Simple HTTPS server for testing GoTLS capture

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := flag.String("port", "8445", "Port to listen on")
	cert := flag.String("cert", "", "Certificate file path")
	key := flag.String("key", "", "Private key file path")
	flag.Parse()

	if *cert == "" || *key == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -cert <cert_file> -key <key_file> [-port <port>]\n", os.Args[0])
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request from %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>eCapture Go HTTPS Test Server</h1><p>Request received successfully!</p></body></html>")
	})

	http.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("API request from %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","message":"eCapture GoTLS test endpoint"}`)
	})

	addr := "127.0.0.1:" + *port
	log.Printf("Starting HTTPS server on %s", addr)
	log.Printf("Certificate: %s", *cert)
	log.Printf("Key: %s", *key)

	if err := http.ListenAndServeTLS(addr, *cert, *key, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
