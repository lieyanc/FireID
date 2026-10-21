package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    Config
		cookie string
	}{
		{"https host-only gets the __Host- prefix", Config{SecureCookies: true}, HostSessionCookie},
		{"shared domain cannot use the prefix", Config{SecureCookies: true, CookieDomain: "example.com"}, SessionCookie},
		{"plain http", Config{}, SessionCookie},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{cfg: tc.cfg}
			rec := httptest.NewRecorder()
			s.SetSessionCookie(rec, "tok", time.Now().Add(time.Hour))
			set := rec.Result().Cookies()
			if len(set) != 1 || set[0].Name != tc.cookie {
				t.Fatalf("set %v, want one %s", set, tc.cookie)
			}
			c := set[0]
			if c.Name == HostSessionCookie && (!c.Secure || c.Domain != "" || c.Path != "/") {
				t.Fatalf("__Host- cookie without Secure, with a Domain or off /: %+v", c)
			}

			// Only the configured name is read back.
			for _, name := range []string{SessionCookie, HostSessionCookie} {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(&http.Cookie{Name: name, Value: "tok"})
				got := s.SessionTokenFromRequest(r)
				if (name == tc.cookie) != (got == "tok") {
					t.Fatalf("cookie %s read as %q", name, got)
				}
			}
		})
	}

	t.Run("sign-out also clears the legacy name", func(t *testing.T) {
		s := &Service{cfg: Config{SecureCookies: true}}
		rec := httptest.NewRecorder()
		s.ClearSessionCookie(rec)
		cleared := map[string]bool{}
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge < 0 {
				cleared[c.Name] = true
			}
		}
		if !cleared[HostSessionCookie] || !cleared[SessionCookie] {
			t.Fatalf("cleared %v", cleared)
		}
	})
}
