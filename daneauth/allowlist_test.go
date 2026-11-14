package daneauth

import "testing"

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
	empty, err := ParseAllowlist(nil)
	if err != nil || !empty.Allows("anything") {
		t.Error("empty allowlist should allow everything")
	}
	if _, err := ParseAllowlist([]string{""}); err == nil {
		t.Error("empty entry should error")
	}
	if _, err := ParseAllowlist([]string{"."}); err == nil {
		t.Error("dot alone should error")
	}
}
