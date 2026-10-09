// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

var (
	mode      = flag.String("mode", "tcp", "receiver mode: tcp or ws")
	listen    = flag.String("listen", "127.0.0.1:0", "listen address")
	readyFile = flag.String("ready-file", "", "file receiving the sink URI")
	output    = flag.String("output", "", "raw output file")
)

func main() {
	flag.Parse()
	if *readyFile == "" || *output == "" {
		fatalf("--ready-file and --output are required")
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fatalf("open output: %v", err)
	}
	defer file.Close()

	switch *mode {
	case "tcp":
		writeReady("tcp://" + listener.Addr().String())
		conn, err := listener.Accept()
		if err != nil {
			fatalf("accept: %v", err)
		}
		_, copyErr := io.Copy(file, conn)
		closeErr := conn.Close()
		if err := file.Sync(); err != nil {
			fatalf("sync: %v", err)
		}
		if copyErr != nil {
			fatalf("copy: %v", copyErr)
		}
		if closeErr != nil {
			fatalf("close connection: %v", closeErr)
		}
	case "ws":
		serveWebSocket(listener, file)
	default:
		fatalf("unsupported mode %q", *mode)
	}
}

func serveWebSocket(listener net.Listener, file *os.File) {
	done := make(chan error, 1)
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/", websocket.Handler(func(conn *websocket.Conn) {
		var receiveErr error
		for {
			var frame []byte
			if err := websocket.Message.Receive(conn, &frame); err != nil {
				if err != io.EOF {
					receiveErr = err
				}
				break
			}
			if _, err := file.Write(frame); err != nil {
				receiveErr = err
				break
			}
		}
		if err := file.Sync(); receiveErr == nil {
			receiveErr = err
		}
		once.Do(func() { done <- receiveErr })
	}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			once.Do(func() { done <- err })
		}
	}()
	writeReady("ws://" + listener.Addr().String() + "/")
	if err := <-done; err != nil {
		fatalf("websocket receive: %v", err)
	}
	_ = server.Close()
}

func writeReady(value string) {
	if err := os.WriteFile(*readyFile, []byte(value+"\n"), 0600); err != nil {
		fatalf("write ready file: %v", err)
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
