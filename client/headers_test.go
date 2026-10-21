package client

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
)

// identityProbe records what the handler behind the middleware sees.
type identityProbe struct {
	called  bool
	id      *HeaderIdentity
	present bool
	headers http.Header
}

func (p *identityProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.called = true
	p.id, p.present = IdentityFrom(r.Context())
	p.headers = r.Header.Clone()
	w.WriteHeader(http.StatusNoContent)
}

func TestTrustedHeaders(t *testing.T) {
	// Headers arrive canonicalised from the server; one is planted with a
	// raw key the way a careless middleware might, to show stripping covers
	// that spelling too.
	full := http.Header{}
	full.Set("X-FireID-Sub", "42")
	full.Set("X-FireID-User", "ann")
	full.Set("X-FireID-Email", "ann@example.test")
	full.Set("X-FireID-Name", "Ann Éxample\x00\x1f")
	full.Set("X-FireID-Groups", "ops, dev,,admins")
	full.Set("X-Other", "stays")
	full["x-fireid-extra"] = []string{"kept only when trusted"}
	anonymous := http.Header{}
	anonymous.Set("X-FireID-User", "ann")
	// A repeated header, under one spelling or two: the proxy replaces
	// these, so a second value came from somewhere else.
	repeated := full.Clone()
	repeated.Add("X-FireID-Sub", "43")
	repeatedGroups := full.Clone()
	repeatedGroups.Add("X-FireID-Groups", "admins")
	repeatedSpelling := full.Clone()
	repeatedSpelling["x-fireid-sub"] = []string{"43"}
	want := &HeaderIdentity{Subject: "42", Username: "ann", Email: "ann@example.test", Name: "Ann Éxample", Groups: []string{"ops", "dev", "admins"}}

	cases := map[string]struct {
		th       TrustedHeaders
		remote   string
		headers  http.Header
		status   int
		present  bool
		stripped bool
	}{
		"loopback v4":        {TrustedHeaders{}, "127.0.0.1:4321", full, http.StatusNoContent, true, false},
		"loopback v6":        {TrustedHeaders{}, "[::1]:4321", full, http.StatusNoContent, true, false},
		"loopback mapped":    {TrustedHeaders{}, "[::ffff:127.0.0.1]:4321", full, http.StatusNoContent, true, false},
		"loopback 127.5":     {TrustedHeaders{}, "127.5.6.7:1", full, http.StatusNoContent, true, false},
		"untrusted lan":      {TrustedHeaders{}, "10.0.0.9:555", full, http.StatusNoContent, false, true},
		"untrusted required": {TrustedHeaders{Required: true}, "10.0.0.9:555", full, http.StatusUnauthorized, false, true},
		"unparseable":        {TrustedHeaders{}, "@", full, http.StatusNoContent, false, true},
		"empty remote":       {TrustedHeaders{}, "", full, http.StatusNoContent, false, true},
		"custom proxies": {
			TrustedHeaders{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			"10.0.0.9:555", full, http.StatusNoContent, true, false,
		},
		"custom excludes loopback": {
			TrustedHeaders{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			"127.0.0.1:1", full, http.StatusNoContent, false, true,
		},
		"trusted anonymous":          {TrustedHeaders{}, "127.0.0.1:1", anonymous, http.StatusNoContent, false, false},
		"trusted anonymous required": {TrustedHeaders{Required: true}, "127.0.0.1:1", http.Header{}, http.StatusUnauthorized, false, false},
		"required with identity":     {TrustedHeaders{Required: true}, "127.0.0.1:1", full, http.StatusNoContent, true, false},
		"repeated sub":               {TrustedHeaders{}, "127.0.0.1:1", repeated, http.StatusNoContent, false, true},
		"repeated sub required":      {TrustedHeaders{Required: true}, "127.0.0.1:1", repeated, http.StatusUnauthorized, false, true},
		"repeated groups":            {TrustedHeaders{}, "127.0.0.1:1", repeatedGroups, http.StatusNoContent, false, true},
		"repeated under a spelling":  {TrustedHeaders{}, "127.0.0.1:1", repeatedSpelling, http.StatusNoContent, false, true},
		"unix socket":                {TrustedHeaders{TrustUnixSocket: true}, "", full, http.StatusNoContent, true, false},
		"unix abstract":              {TrustedHeaders{TrustUnixSocket: true}, "@", full, http.StatusNoContent, true, false},
		"unix path":                  {TrustedHeaders{TrustUnixSocket: true}, "/run/app.sock", full, http.StatusNoContent, true, false},
		"unix flag keeps loopback":   {TrustedHeaders{TrustUnixSocket: true}, "127.0.0.1:1", full, http.StatusNoContent, true, false},
		"unix flag not tcp":          {TrustedHeaders{TrustUnixSocket: true}, "10.0.0.9:555", full, http.StatusNoContent, false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			probe := &identityProbe{}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			req.Header = tc.headers.Clone()
			rec := httptest.NewRecorder()
			tc.th.Middleware(probe).ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			if tc.status == http.StatusUnauthorized {
				if probe.called {
					t.Fatal("next handler ran on a 401")
				}
				return
			}
			if !probe.called {
				t.Fatal("next handler did not run")
			}
			if probe.present != tc.present {
				t.Fatalf("identity present %v, want %v", probe.present, tc.present)
			}
			if tc.present && !reflect.DeepEqual(probe.id, want) {
				t.Fatalf("identity %+v, want %+v", probe.id, want)
			}
			for k := range probe.headers {
				if len(k) >= 9 && http.CanonicalHeaderKey(k[:9]) == headerPrefix && tc.stripped {
					t.Errorf("header %s reached the handler from an untrusted address", k)
				}
			}
			if tc.stripped {
				if probe.headers.Get("X-Other") != "stays" {
					t.Error("unrelated headers must stay")
				}
			} else if tc.headers.Get("X-FireID-Sub") != "" && probe.headers.Get("X-FireID-Sub") != "42" {
				t.Error("trusted headers must reach the handler")
			}
		})
	}
}

func TestIdentityFromEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if id, ok := IdentityFrom(req.Context()); ok || id != nil {
		t.Fatal("identity without middleware")
	}
}

func TestCleanHeader(t *testing.T) {
	cases := map[string]string{
		"plain":            "plain",
		"  spaced  ":       "spaced",
		"tab\tin":          "tabin",
		"nl\r\nin":         "nlin",
		"del\x7fin":        "delin",
		"\xe4\xb8\xad\xe6": "\xe4\xb8\xad\xe6", // raw bytes stay, valid UTF-8 or not
		"":                 "",
	}
	for in, want := range cases {
		if got := cleanHeader(in); got != want {
			t.Errorf("cleanHeader(%q) = %q, want %q", in, got, want)
		}
	}
}
