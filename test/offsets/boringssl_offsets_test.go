// Package offsets validates the per-Android-version BoringSSL TLS 1.3 traffic-secret
// offset headers (kern/boringssl_a_<N>_kern.c) so a missing or shifted define can't
// silently regress into unusable keylog output.
//
// Android 16+ exposes the application-traffic secrets as public
// InplaceVector<uint8_t,48> members of bssl::SSL3_STATE (write_traffic_secret,
// read_traffic_secret, exporter_secret — consecutive: 48 bytes storage + 1 size_
// byte, step 0x31). uretprobe_bssl_do_handshake reads them via
// BSSL__SSL3_STATE_{SERVER,CLIENT}_TRAFFIC_SECRET_0 and their _LEN (size_) macros.
// If a version header omits those four defines, boringssl_masterkey.h falls back to
// shared older-layout defaults (client 0x150, lens 0x1b0/0x1b1), shifting the client
// secret and reading hash_len from unrelated memory — the exact bug this guards.
package offsets

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

var defineRe = regexp.MustCompile(`(?m)^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)`)

func parseDefines(t *testing.T, path string) map[string]int64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]int64{}
	for _, m := range defineRe.FindAllStringSubmatch(string(b), -1) {
		v, err := strconv.ParseInt(m[2], 0, 64)
		if err != nil {
			continue
		}
		out[m[1]] = v
	}
	return out
}

func TestBoringSSLTrafficSecretOffsets(t *testing.T) {
	files, err := filepath.Glob("../../kern/boringssl_a_*_kern.c")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no boringssl_a_*_kern.c headers found")
	}
	const (
		server    = "BSSL__SSL3_STATE_SERVER_TRAFFIC_SECRET_0"
		client    = "BSSL__SSL3_STATE_CLIENT_TRAFFIC_SECRET_0"
		serverLen = "BSSL__SSL3_STATE_SERVER_TRAFFIC_SECRET_0_LEN"
		clientLen = "BSSL__SSL3_STATE_CLIENT_TRAFFIC_SECRET_0_LEN"
		step      = 0x31 // InplaceVector<uint8_t,48>: 48 storage + 1 size_ byte
	)
	sawA16plus := false
	for _, f := range files {
		d := parseDefines(t, f)
		if _, isA16plus := d["BSSL__SSL3_STATE_VERSION"]; !isA16plus {
			// Pre-A16 (raw-array) layout: client=server+0x30, separate secret_length
			// region. A different valid layout owned by masterkey.h / the older headers;
			// not the InplaceVector invariants checked below.
			continue
		}
		sawA16plus = true
		missing := false
		for _, k := range []string{server, client, serverLen, clientLen} {
			if _, ok := d[k]; !ok {
				t.Errorf("%s: missing %s — masterkey.h would fall back to wrong-layout defaults", f, k)
				missing = true
			}
		}
		if missing {
			continue
		}
		if got, want := d[client], d[server]+step; got != want {
			t.Errorf("%s: CLIENT_TRAFFIC_SECRET_0=0x%x, want SERVER+0x31=0x%x", f, got, want)
		}
		if got, want := d[serverLen], d[client]-1; got != want {
			t.Errorf("%s: SERVER_TRAFFIC_SECRET_0_LEN=0x%x, want CLIENT-1=0x%x", f, got, want)
		}
		if got, want := d[clientLen], d[serverLen]+step; got != want {
			t.Errorf("%s: CLIENT_TRAFFIC_SECRET_0_LEN=0x%x, want SERVER_LEN+0x31=0x%x", f, got, want)
		}
		if delta := d[serverLen] - d[server]; delta < 0x20 || delta > 0x30 {
			t.Errorf("%s: SERVER size_ byte 0x%x not 32..48 past storage 0x%x", f, d[serverLen], d[server])
		}
	}
	if !sawA16plus {
		t.Fatal("expected at least one Android 16+ header (a_16/a_17) with SSL3_STATE traffic-secret offsets")
	}
}
