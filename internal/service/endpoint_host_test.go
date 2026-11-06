package service

import "testing"

func TestNormalizeEndpointHost(t *testing.T) {
	cases := []struct{ host, domain, want string }{
		{"www", "example.com", "www.example.com"},
		{"www.example.com", "example.com", "www.example.com"},
		{"example.com", "example.com", "example.com"},
		{"WWW.Example.COM.", "example.com", "www.example.com"},
		{"api.v1", "example.com", "api.v1.example.com"},
	}
	for _, c := range cases {
		got, err := normalizeEndpointHost(c.host, c.domain)
		if err != nil {
			t.Fatalf("%q + %q: %v", c.host, c.domain, err)
		}
		if got != c.want {
			t.Fatalf("%q + %q = %q, want %q", c.host, c.domain, got, c.want)
		}
	}
}
