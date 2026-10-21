package forwardauth

import (
	"strings"
	"testing"
)

func TestSameOriginOr(t *testing.T) {
	const origin = "https://site.example"
	for raw, want := range map[string]string{
		"https://site.example/a?b=1":    "https://site.example/a?b=1",
		"https://SITE.example/a":        "https://SITE.example/a",
		"https://evil.example/":         origin + "/",
		"//evil.example/":               origin + "/",
		"/relative":                     origin + "/",
		"javascript:alert(1)":           origin + "/",
		"https://user@site.example/":    origin + "/",
		"http://site.example/downgrade": origin + "/",
		"":                              origin + "/",
	} {
		if got := sameOriginOr(raw, origin); got != want {
			t.Errorf("sameOriginOr(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestCookieNames(t *testing.T) {
	if !strings.HasPrefix(sessionCookie(true), "__Host-") || !strings.HasPrefix(stateCookie(true), "__Host-") {
		t.Fatal("HTTPS cookies must carry the __Host- prefix")
	}
	if strings.HasPrefix(sessionCookie(false), "__Host-") {
		t.Fatal("browsers drop __Host- cookies without Secure")
	}
}

func TestNginxSnippetQuotesSlug(t *testing.T) {
	s := NginxServerSnippet("app-a", "http://127.0.0.1:8099/")
	for _, want := range []string{
		`proxy_set_header X-FireID-App "app-a";`,
		"proxy_pass http://127.0.0.1:8099/api/authz/forward;",
		"proxy_pass http://127.0.0.1:8099/api/authz/app/;",
		"location = /__fireid/authz {\n    internal;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("snippet lacks %q:\n%s", want, s)
		}
	}
}
