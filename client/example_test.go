package client_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lieyanc/FireID/client"
)

// sessions stands for the application's own session store.
var sessions struct {
	create       func(w http.ResponseWriter, subject, sid string)
	endBySID     func(sid string) error
	endBySubject func(subject string) error
}

// Example_login wires the browser flow into a net/http server: /auth/login
// starts a login, /auth/callback finishes it and hands the verified claims
// to OnLogin, which creates the application's session.
func Example_login() {
	ctx := context.Background()
	c, err := client.New(ctx, client.Config{
		Issuer:       "https://id.example.com",
		ClientID:     "my-app",
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:  "https://app.example.com/auth/callback",
	})
	if err != nil {
		log.Fatal(err)
	}

	flow := client.FlowConfig{
		OnLogin: func(w http.ResponseWriter, r *http.Request, res *client.LoginResult) error {
			// Key the session on the subject, never on the username, and
			// keep the provider's session ID for back-channel logout.
			sessions.create(w, res.Claims.Subject, res.Claims.SID)
			http.Redirect(w, r, res.ReturnTo, http.StatusFound)
			return nil
		},
		// Ask Fire ID for two factors; check res.Claims.ACR in OnLogin.
		AuthOptions: []client.AuthOption{client.WithACRValues("urn:fireid:loa:2")},
	}

	mux := http.NewServeMux()
	mux.Handle("GET /auth/login", c.LoginHandler(flow))
	mux.Handle("GET /auth/callback", c.CallbackHandler(flow))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Not signed in: send the browser to /auth/login?return=<this path>.
		http.Redirect(w, r, "/auth/login?return="+r.URL.Path, http.StatusFound)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}

// ExampleClient_Exchange drives the code flow by hand, for an application
// that keeps the state, nonce and verifier in its own session store.
func ExampleClient_Exchange() {
	ctx := context.Background()
	c, err := client.New(ctx, client.Config{
		Issuer:      "https://id.example.com",
		ClientID:    "cli-tool", // a public client: PKCE only
		RedirectURL: "http://127.0.0.1:9876/callback",
	})
	if err != nil {
		log.Fatal(err)
	}
	state, nonce, verifier := client.RandomString(), client.RandomString(), client.NewPKCEVerifier()
	fmt.Println("open:", c.AuthCodeURL(state, nonce, verifier))

	// ... the browser comes back to the redirect URL with ?code=...&state=...
	// Compare state with what was sent, then:
	var code string
	tokens, err := c.Exchange(ctx, code, verifier, client.WithNonce(nonce))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signed in as", tokens.Claims.Subject)

	// Later, with the refresh token (needs the offline_access scope):
	fresh, err := c.Refresh(ctx, tokens.RefreshToken, client.WithExpectedSubject(tokens.Claims.Subject))
	if err != nil {
		log.Fatal(err)
	}
	_ = fresh.AccessToken
}

// ExampleClient_BackchannelLogoutHandler serves the URI registered as the
// application's back-channel logout URI. Fire ID POSTs a logout token there
// whenever a session that signed in to the application ends.
func ExampleClient_BackchannelLogoutHandler() {
	ctx := context.Background()
	c, err := client.New(ctx, client.Config{
		Issuer:       "https://id.example.com",
		ClientID:     "my-app",
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:  "https://app.example.com/auth/callback",
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /auth/backchannel-logout", c.BackchannelLogoutHandler(func(ctx context.Context, lt *client.LogoutToken) error {
		// End the sessions created from the provider session lt.SID; when
		// there is no SID, every session of lt.Subject. Return an error
		// only for a transient failure: the provider then retries.
		if lt.SID != "" {
			return sessions.endBySID(lt.SID)
		}
		return sessions.endBySubject(lt.Subject)
	}))
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}

// ExampleTrustedHeaders_Middleware protects an application that has no
// login of its own and sits behind Fire ID's forward auth: nginx sets the
// X-FireID-* headers and nothing else may.
func ExampleTrustedHeaders_Middleware() {
	th := client.TrustedHeaders{Required: true} // trusts loopback only
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		id, _ := client.IdentityFrom(r.Context()) // present: Required is set
		fmt.Fprintf(w, "hello %s (%s)\n", id.Username, id.Subject)
	})
	// Bind to loopback: the headers are trusted only because nothing but
	// nginx can reach this listener.
	log.Fatal(http.ListenAndServe("127.0.0.1:3000", th.Middleware(mux)))
}
