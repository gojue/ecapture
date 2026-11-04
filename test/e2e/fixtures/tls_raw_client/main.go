// Command tls_raw_client exchanges binary data with the --raw TLS fixture.
// It never configures KeyLogWriter: capture secrets must come from eCapture.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func main() {
	address := flag.String("address", "", "loopback TLS server address")
	token := flag.String("token", "ECAPTURE_E2E_OK", "binary marker prefix")
	flag.Parse()
	if err := exchange(*address, *token); err != nil {
		log.Fatal(err)
	}
}

func exchange(address, token string) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true, // Ephemeral loopback certificate.
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	greeting := append([]byte{0, 0xff}, []byte(token+"_SERVER\n")...)
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, greeting) {
		return fmt.Errorf("server-first greeting mismatch")
	}
	request := append([]byte{0, 0xff}, []byte(token+"_CLIENT\n")...)
	for _, chunk := range [][]byte{request[:2], request[2:]} {
		if _, err := conn.Write(chunk); err != nil {
			return err
		}
	}
	ack, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(ack, []byte{0x7f}) {
		return fmt.Errorf("server did not acknowledge exact client bytes")
	}
	return nil
}
