package auth

import (
	"sync"
	"time"
)

// Throttle limits failed attempts per key. It follows the workspace convention:
// a handful of free attempts, then a lockout that doubles up to a ceiling. The
// counters live in memory — a restart clears them, which is acceptable because
// an attacker who can restart the service has already won, and every lockout is
// also recorded in the audit log.
type Throttle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry

	free     int
	base     time.Duration
	max      time.Duration
	window   time.Duration
	nowFn    func() time.Time
	lastGC   time.Time
	gcPeriod time.Duration
}

type throttleEntry struct {
	failures  int
	lockedTil time.Time
	last      time.Time
}

// ThrottleOptions tunes a Throttle. Zero values fall back to the defaults.
type ThrottleOptions struct {
	// Free is how many failures are allowed before locking starts.
	Free int
	// Base is the first lockout duration; each further failure doubles it.
	Base time.Duration
	// Max caps the lockout duration.
	Max time.Duration
	// Window is how long a failure is remembered.
	Window time.Duration
}

// NewThrottle builds a Throttle with the given options.
func NewThrottle(opts ThrottleOptions) *Throttle {
	if opts.Free <= 0 {
		opts.Free = 5
	}
	if opts.Base <= 0 {
		opts.Base = time.Minute
	}
	if opts.Max <= 0 {
		opts.Max = 15 * time.Minute
	}
	if opts.Window <= 0 {
		opts.Window = 15 * time.Minute
	}
	return &Throttle{
		entries:  map[string]*throttleEntry{},
		free:     opts.Free,
		base:     opts.Base,
		max:      opts.Max,
		window:   opts.Window,
		nowFn:    func() time.Time { return time.Now() },
		gcPeriod: 5 * time.Minute,
	}
}

// SetClock replaces the clock. Tests only.
func (t *Throttle) SetClock(fn func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nowFn = fn
}

// RetryAfter reports how long the key must wait before another attempt. A zero
// duration means attempts are allowed.
func (t *Throttle) RetryAfter(key string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()

	e, ok := t.entries[key]
	if !ok {
		return 0
	}
	now := t.nowFn()
	if now.After(e.last.Add(t.window)) {
		delete(t.entries, key)
		return 0
	}
	if e.lockedTil.After(now) {
		return e.lockedTil.Sub(now)
	}
	return 0
}

// Fail records a failed attempt and returns the lockout now in effect, if any.
func (t *Throttle) Fail(key string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.nowFn()
	e, ok := t.entries[key]
	if !ok || now.After(e.last.Add(t.window)) {
		e = &throttleEntry{}
		t.entries[key] = e
	}
	e.last = now

	// Count consecutive failures inside the window.
	e.failures++
	if e.failures <= t.free {
		return 0
	}
	// Each failure past the free allowance doubles the lockout, capped at Max.
	over := e.failures - t.free - 1
	lock := t.base
	for i := 0; i < over && lock < t.max; i++ {
		lock *= 2
	}
	if lock > t.max {
		lock = t.max
	}
	e.lockedTil = now.Add(lock)
	return lock
}

// Reset clears the key, which a successful sign-in does.
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// gcLocked drops stale entries so a stream of distinct keys (for example, one
// per source address) cannot grow the map without bound.
func (t *Throttle) gcLocked() {
	now := t.nowFn()
	if now.Sub(t.lastGC) < t.gcPeriod {
		return
	}
	t.lastGC = now
	for k, e := range t.entries {
		if now.After(e.last.Add(t.window)) && !e.lockedTil.After(now) {
			delete(t.entries, k)
		}
	}
}
