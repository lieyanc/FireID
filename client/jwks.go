package client

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// jwksRefetchInterval bounds how often a cached key set is fetched again,
	// whether for an unknown kid, for its age or after a failed attempt. A
	// rotation is picked up at the first token signed with the new key; a
	// stream of made-up kids, or a provider that is down, cannot make the
	// client hammer it.
	jwksRefetchInterval = 30 * time.Second
	// jwksMaxAge is how long a fetched key set is used before it is
	// refreshed on the next lookup, so a key the provider retired stops
	// verifying within the hour even though its kid is still cached. A
	// failed refresh keeps the cached set.
	jwksMaxAge = time.Hour
)

// keySet is the provider's JWKS, fetched on first use and cached. The first
// fetch is made under the mutex, since every caller needs it. Later ones —
// for an unknown kid or a set older than jwksMaxAge — run outside it, one at
// a time and at most once per jwksRefetchInterval, so a cached key keeps
// verifying while the provider is slow or down.
type keySet struct {
	url  string
	http *http.Client
	now  func() time.Time

	mu        sync.Mutex
	keys      map[string]*jwk
	fetchedAt time.Time
	// lastAttempt is when a refresh of the cached set was last started; the
	// next one waits jwksRefetchInterval, whether this one succeeded or not.
	lastAttempt time.Time
	// lastErr is why the last refresh failed, nil after a success. An
	// unknown kid is reported with it while the rate limit holds, since
	// whether the key exists could not be found out.
	lastErr error
	// inflight is closed when the refresh in progress finishes; nil when
	// none is.
	inflight chan struct{}
}

// key returns the key with the given kid. An empty kid matches a published
// key that has none. With the set cached and fresh, a known kid is answered
// at once; otherwise a refresh is started, or waited for when one is in
// progress and the kid is unknown. A known kid in a stale set is served
// without waiting.
func (ks *keySet) key(ctx context.Context, kid string) (*jwk, error) {
	ks.mu.Lock()
	if ks.keys == nil {
		// Nothing is cached yet, so every caller needs this fetch: it is
		// made under the mutex and all of them wait for it.
		keys, err := ks.fetch(ctx)
		if err != nil {
			ks.mu.Unlock()
			return nil, err
		}
		ks.keys, ks.fetchedAt = keys, ks.now()
	}
	now := ks.now()
	k, known := ks.keys[kid]
	if known && now.Sub(ks.fetchedAt) <= jwksMaxAge {
		ks.mu.Unlock()
		return k, nil
	}
	done := ks.inflight
	switch {
	case done == nil && now.Sub(ks.lastAttempt) >= jwksRefetchInterval:
		// This caller refreshes the set, with the mutex released so that
		// cached keys keep verifying meanwhile.
		done = make(chan struct{})
		ks.inflight, ks.lastAttempt = done, now
		ks.mu.Unlock()
		keys, err := ks.fetch(ctx)
		ks.mu.Lock()
		if err == nil {
			ks.keys, ks.fetchedAt = keys, now
		}
		ks.lastErr, ks.inflight = err, nil
		close(done)
	case known:
		// Stale but cached: serve it. The refresh in progress, or the next
		// one the rate limit allows, replaces the set.
		ks.mu.Unlock()
		return k, nil
	case done != nil:
		// Another caller is fetching; the kid may be in what they get.
		ks.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: fetch JWKS: %v", ErrProvider, ctx.Err())
		}
		ks.mu.Lock()
	}
	k, known = ks.keys[kid]
	err := ks.lastErr
	ks.mu.Unlock()
	switch {
	case known:
		return k, nil
	case err != nil:
		return nil, err
	default:
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
}

// fetch gets the key set from the provider and returns it by kid. When two
// keys share a kid the first wins; a provider that publishes that is broken
// anyway, and picking one deterministically beats letting a later entry
// shadow an earlier one.
func (ks *keySet) fetch(ctx context.Context) (map[string]*jwk, error) {
	body, err := getJSON(ctx, ks.http, ks.url)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	list, err := parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS: %v", ErrProvider, err)
	}
	keys := make(map[string]*jwk, len(list))
	for _, k := range list {
		if _, dup := keys[k.kid]; !dup {
			keys[k.kid] = k
		}
	}
	return keys, nil
}
