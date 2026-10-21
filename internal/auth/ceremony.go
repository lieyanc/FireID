package auth

import (
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ceremonyTTL is how long a passkey prompt may stay open. Browsers time the
// prompt out after the five minutes the options ask for; a little slack covers
// the round trip.
const ceremonyTTL = 6 * time.Minute

// maxCeremonies bounds the pending ceremonies. Starting a sign-in ceremony
// needs no account, so without a ceiling anyone could fill memory with them.
const maxCeremonies = 10_000

// ceremony is the server half of a WebAuthn exchange: the challenge and what
// the browser's answer must match. It never leaves the process; the browser
// holds only its random id.
type ceremony struct {
	data webauthn.SessionData
	// userID and sessionID bind a registration to the account and the
	// browser session that started it. Both are 0 for a sign-in.
	userID    int64
	sessionID int64
	expires   time.Time
}

// ceremonies holds pending WebAuthn exchanges in memory. A restart loses them,
// which only means a person has to press the passkey button again.
type ceremonies struct {
	mu      sync.Mutex
	pending map[string]ceremony
	now     func() time.Time
}

func newCeremonies(now func() time.Time) *ceremonies {
	return &ceremonies{pending: map[string]ceremony{}, now: now}
}

// put stores c under a fresh id. It fails with a RateLimitError when the table
// is full of live ceremonies.
func (cs *ceremonies) put(c ceremony) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := cs.now()
	if len(cs.pending) >= maxCeremonies {
		for k, v := range cs.pending {
			if now.After(v.expires) {
				delete(cs.pending, k)
			}
		}
		if len(cs.pending) >= maxCeremonies {
			return "", &RateLimitError{RetryAfter: time.Minute}
		}
	}
	c.expires = now.Add(ceremonyTTL)
	cs.pending[id] = c
	return id, nil
}

// take removes and returns the ceremony, so each challenge is answered at most
// once — also when the answer is wrong.
func (cs *ceremonies) take(id string) (ceremony, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.pending[id]
	if !ok {
		return ceremony{}, false
	}
	delete(cs.pending, id)
	if cs.now().After(c.expires) {
		return ceremony{}, false
	}
	return c, true
}
