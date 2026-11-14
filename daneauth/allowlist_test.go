package daneauth

import (
	"strings"
	"testing"
)

func TestAllowlist(t *testing.T) {
	a, err := ParseAllowlist([]string{"mta1.example.com", ".devices.example.org."})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want bool
	}{
		{"MTA1.example.com", true},
		{"mta1.example.com.", true},
		{"x.mta1.example.com", false},
		{"devices.example.org", true},
		{"a.b.devices.example.org", true},
		{"baddevices.example.org", false},
		{"example.org", false},
	}
	for _, c := range cases {
		if got := a.Allows(c.name); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	var nilList *Allowlist
	if !nilList.Allows("anything") {
		t.Error("nil allowlist should allow everything")
	}
	if _, err := ParseAllowlist(nil); err == nil {
		t.Error("nil list should error")
	}
	if _, err := ParseAllowlist([]string{}); err == nil {
		t.Error("empty list should error")
	}
	if _, err := ParseAllowlist([]string{"."}); err == nil {
		t.Error("dot alone should error")
	}
}

func TestAllowlistBadEntries(t *testing.T) {
	for _, e := range []string{"", "  ", "..x.com", "*.example.com", ".*.example.com", "a b", "a..b", "x.com..", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com", "a@b.com"} {
		if _, err := ParseAllowlist([]string{"ok.example.com", e}); err == nil {
			t.Errorf("entry %q should error", e)
		} else if e != "" && !strings.Contains(err.Error(), "invalid allowlist entry") {
			t.Errorf("entry %q: unexpected error %v", e, err)
		}
	}
}

func TestAllowlistTrimsWhitespace(t *testing.T) {
	a, err := ParseAllowlist([]string{"  Host.Example.com\t", " .Dev.example.org. "})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"host.example.com", "x.dev.example.org", "dev.example.org"} {
		if !a.Allows(n) {
			t.Errorf("Allows(%q) = false", n)
		}
	}
	if a.Allows("example.com") {
		t.Error("example.com should not match")
	}
}
