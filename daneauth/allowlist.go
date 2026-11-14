package daneauth

import (
	"errors"
	"fmt"
	"strings"
)

// Allowlist restricts which client names a server accepts. A nil
// *Allowlist means "no restriction" (every name is allowed); a non-nil
// Allowlist, which ParseAllowlist guarantees is non-empty, allows only the
// names it lists.
type Allowlist struct {
	exact  map[string]bool
	suffix []string // domains; each matches itself and any name below it
}

func normalize(name string) string {
	name = strings.ToLower(name)
	return strings.TrimSuffix(name, ".")
}

// validHostname reports whether n (already without a trailing dot) is a
// plausible DNS name: non-empty labels of at most 63 octets drawn from
// [A-Za-z0-9_-], and at most 253 octets overall.
func validHostname(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// ParseAllowlist builds an Allowlist. An entry "name" matches exactly;
// ".domain" matches the domain itself and any name below it. Matching is
// case-insensitive and ignores one trailing dot. Surrounding whitespace in
// an entry is trimmed. Each entry must be a valid DNS name (labels of
// [A-Za-z0-9_-], at most 63 octets each, at most 253 overall); wildcards
// are rejected. An empty list is an error.
func ParseAllowlist(entries []string) (*Allowlist, error) {
	if len(entries) == 0 {
		return nil, errors.New("daneauth: allowlist has no entries")
	}
	a := &Allowlist{exact: map[string]bool{}}
	for _, e := range entries {
		t := strings.TrimSpace(e)
		isSuffix := strings.HasPrefix(t, ".")
		if isSuffix {
			t = t[1:]
		}
		t = strings.TrimSuffix(t, ".")
		if !validHostname(t) {
			return nil, fmt.Errorf("daneauth: invalid allowlist entry %q", e)
		}
		t = strings.ToLower(t)
		if isSuffix {
			a.suffix = append(a.suffix, t)
		} else {
			a.exact[t] = true
		}
	}
	return a, nil
}

// Allows reports whether name is permitted. A nil Allowlist allows
// everything.
func (a *Allowlist) Allows(name string) bool {
	if a == nil {
		return true
	}
	n := normalize(name)
	if a.exact[n] {
		return true
	}
	for _, d := range a.suffix {
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	return false
}
