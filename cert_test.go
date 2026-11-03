package main

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	c := newTestChain(t, false)
	other := newTestChain(t, false)
	expired := newTestChain(t, true)
	tests := []struct {
		name      string
		cert, key []byte
		domains   []string
		bad       bool
	}{
		{"valid", c.Cert, c.Key, []string{"example.com", "*.example.com", "a.example.com"}, false},
		{"wrong key", c.Cert, other.Key, []string{"example.com"}, true},
		{"expired", expired.Cert, expired.Key, []string{"example.com"}, true},
		{"wrong domain", c.Cert, c.Key, []string{"elsewhere.com"}, true},
		{"wrong wildcard", c.Cert, c.Key, []string{"*.elsewhere.com"}, true},
		{"leaf only", c.Leaf, c.Key, []string{"example.com"}, true},
		{"duplicate leaf", append(append([]byte{}, c.Leaf...), c.Leaf...), c.Key, []string{"example.com"}, true},
		{"junk", append(append([]byte{}, c.Cert...), []byte("junk")...), c.Key, []string{"example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.cert, tt.key, tt.domains, time.Now(), c.Roots)
			if (err != nil) != tt.bad {
				t.Fatalf("err=%v wantBad=%v", err, tt.bad)
			}
		})
	}
	if err := Validate(c.Cert, c.Key, []string{"example.com"}, time.Now(), other.Roots); err == nil {
		t.Fatal("untrusted chain accepted")
	}
}

func TestValidateWildcardGroupCoverage(t *testing.T) {
	for _, tt := range []struct {
		name, group string
		names       []string
		bad         bool
	}{
		{"wildcard and apex", "*.example.com", []string{"*.example.com", "example.com"}, false},
		{"wildcard only", "*.example.com", []string{"*.example.com"}, false},
		{"case insensitive SAN", "*.example.com", []string{"*.EXAMPLE.COM"}, false},
		{"apex only", "*.example.com", []string{"example.com"}, true},
		{"concrete subdomain", "*.example.com", []string{"example.com", "api.example.com"}, true},
		{"different wildcard", "*.example.com", []string{"*.other.com"}, true},
		{"narrower wildcard", "*.example.com", []string{"*.sub.example.com"}, true},
		{"broader wildcard", "*.sub.example.com", []string{"*.example.com"}, true},
		{"plain apex still required", "example.com", []string{"*.example.com"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestChain(t, false, tt.names...)
			err := Validate(c.Cert, c.Key, []string{tt.group}, time.Now(), c.Roots)
			if (err != nil) != tt.bad {
				t.Fatalf("err=%v wantBad=%v", err, tt.bad)
			}
		})
	}
}
