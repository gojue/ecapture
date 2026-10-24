package handlers

import "testing"

func TestNormalizeTextSource(t *testing.T) {
	tests := []struct {
		mode, source, want string
		wantErr            bool
	}{
		{ModeText, "", TextSourceHook, false},
		{ModeText, "HOOK", TextSourceHook, false},
		{ModeText, "Pcapng", TextSourcePcapng, false},
		{ModePcapng, TextSourceHook, TextSourceHook, false},
		{ModeKeylog, TextSourcePcapng, "", true},
		{ModeText, "other", "", true},
	}
	for _, test := range tests {
		got, err := NormalizeTextSource(test.mode, test.source)
		if got != test.want || (err != nil) != test.wantErr {
			t.Errorf("NormalizeTextSource(%q, %q) = %q, %v; want %q, error=%v", test.mode, test.source, got, err, test.want, test.wantErr)
		}
	}
}
