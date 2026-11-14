package daneauth

import (
	"errors"
	"fmt"
	"strings"
)

// Allowlist restricts which client names a server accepts.
type Allowlist struct {
	exact  map[string]bool
	suffix []string // domains; each matches itself and any name below it
}

func normalize(name string) string {
	name = strings.ToLower(name)
	return strings.TrimSuffix(name, ".")
}

// ParseAllowlist builds an Allowlist. An entry "name" matches exactly;
// ".domain" matches the domain itself and any name below it. Matching is
// case-insensitive and ignores one trailing dot.
func ParseAllowlist(entries []string) (*Allowlist, error) {
	a := &Allowlist{exact: map[string]bool{}}
	for _, e := range entries {
		if e == "" {
			return nil, errors.New("daneauth: empty allowlist entry")
		}
		if strings.HasPrefix(e, ".") {
			d := normalize(e[1:])
			if d == "" {
				return nil, fmt.Errorf("daneauth: invalid allowlist entry %q", e)
			}
			a.suffix = append(a.suffix, d)
			continue
		}
		n := normalize(e)
		if n == "" {
			return nil, fmt.Errorf("daneauth: invalid allowlist entry %q", e)
		}
		a.exact[n] = true
	}
	return a, nil
}

// Allows reports whether name is permitted. A nil or empty Allowlist
// allows everything.
func (a *Allowlist) Allows(name string) bool {
	if a == nil || (len(a.exact) == 0 && len(a.suffix) == 0) {
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
