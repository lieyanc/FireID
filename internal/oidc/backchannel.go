package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// Backchannel delivers OpenID Connect Back-Channel Logout 1.0 notifications.
// Ending a browser session queues one row per app the session signed in to
// (a store trigger does that, in the same transaction); this worker signs a
// logout token for each row and POSTs it to the app's back-channel URI,
// retrying with growing delays. It runs apart from the request that ended the
// session, so a slow relying party cannot hold up a sign-out.
type Backchannel struct {
	storage *Storage
	issuer  string
	log     *slog.Logger
	client  *http.Client

	// Interval is how often Run looks for notifications that are due.
	Interval time.Duration
}

const (
	// logoutTokenTTL is how long a logout token stays valid. It only has to
	// outlive the request that carries it.
	logoutTokenTTL = 2 * time.Minute
	// backchannelTimeout bounds one delivery attempt, connection included.
	backchannelTimeout = 5 * time.Second
	// backchannelBatch is how many notifications one pass picks up.
	backchannelBatch = 50
	// backchannelParallel is how many deliveries run at once, so one
	// unreachable relying party does not stall the rest of the batch.
	backchannelParallel = 4
	// backchannelMaxAttempts is the number of tries before a notification is
	// dropped and the failure audited.
	backchannelMaxAttempts = 6
)

// backchannelBackoff[n] is the wait after the (n+1)th failed attempt; the
// last entry repeats. Six attempts span a little under three hours.
var backchannelBackoff = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// NewBackchannel returns a worker for the given issuer. Call Run to start it.
// It reads the current signing key from the store on every pass, so a
// rotated key is picked up without a restart.
func NewBackchannel(st *store.Store, box *secretbox.Box, issuer string, log *slog.Logger) *Backchannel {
	return &Backchannel{
		storage: &Storage{store: st, box: box, log: log},
		issuer:  strings.TrimSuffix(issuer, "/"),
		log:     log,
		client: &http.Client{
			Timeout: backchannelTimeout,
			// A redirect would carry the token somewhere the app's manager
			// did not register; the response is treated as a failure instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Interval: 5 * time.Second,
	}
}

// Run delivers notifications until ctx is cancelled. The first pass happens
// at once, so anything queued while the process was down goes out promptly.
func (b *Backchannel) Run(ctx context.Context) {
	ticker := time.NewTicker(b.Interval)
	defer ticker.Stop()
	for {
		b.Flush(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Flush makes one delivery pass over the notifications that are due and
// returns when every attempt in it has finished. Run calls it on a timer;
// tests call it directly.
func (b *Backchannel) Flush(ctx context.Context) {
	jobs, err := b.storage.store.DueBackchannel(backchannelBatch)
	if err != nil {
		b.log.Warn("could not read pending back-channel logouts", "err", err)
		return
	}
	if len(jobs) == 0 {
		return
	}
	key, err := b.storage.SigningKey(ctx)
	if err != nil {
		b.log.Warn("could not load the signing key for back-channel logout", "err", err)
		return
	}
	signer, err := logoutSigner(key)
	if err != nil {
		b.log.Warn("could not create a signer for back-channel logout", "kid", key.ID(), "err", err)
		return
	}

	var wg sync.WaitGroup
	slots := make(chan struct{}, backchannelParallel)
	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			b.deliver(ctx, signer, job)
		}()
	}
	wg.Wait()
}

// deliver makes one attempt for a job and records the outcome: done, retry
// later, or given up with an audit entry. Every attempt signs a fresh token,
// so a retry never resends an expired one.
func (b *Backchannel) deliver(ctx context.Context, signer jose.Signer, job *store.BackchannelJob) {
	st := b.storage.store
	derr := b.post(ctx, signer, job)
	if derr == nil {
		if err := st.BackchannelDone(job.ID); err != nil {
			b.log.Warn("could not mark back-channel logout delivered", "clientId", job.ClientID, "err", err)
		}
		b.log.Debug("back-channel logout delivered", "clientId", job.ClientID, "uri", job.URI)
		return
	}

	attempt := job.Attempts + 1
	if ctx.Err() != nil {
		// Shutdown cut the attempt short; the row stays due and goes out
		// on the next start without using up a try.
		return
	}
	b.log.Warn("back-channel logout delivery failed", "clientId", job.ClientID, "uri", job.URI,
		"attempt", attempt, "err", derr)
	if attempt < backchannelMaxAttempts {
		next := st.Now().Add(backchannelBackoff[min(job.Attempts, len(backchannelBackoff)-1)])
		if err := st.BackchannelRetry(job.ID, derr.Error(), next); err != nil {
			b.log.Warn("could not reschedule back-channel logout", "clientId", job.ClientID, "err", err)
		}
		return
	}
	if err := st.BackchannelDone(job.ID); err != nil {
		b.log.Warn("could not drop back-channel logout", "clientId", job.ClientID, "err", err)
	}
	if err := st.Audit(store.AuditEvent{
		Event: "backchannel.failed", Severity: store.SeverityWarning, ActorType: store.ActorSystem,
		AppID: job.AppID, UserID: job.UserID,
		Detail: map[string]any{"attempts": attempt, "error": derr.Error()},
	}); err != nil {
		b.log.Warn("could not record audit event", "event", "backchannel.failed", "err", err)
	}
}

// post sends the logout token as Back-Channel Logout 1.0 section 2.5 asks:
// a form POST with a logout_token field, answered by a 2xx. The response
// body means nothing; a little of it is read so the connection can be reused.
func (b *Backchannel) post(ctx context.Context, signer jose.Signer, job *store.BackchannelJob) error {
	token, err := b.logoutToken(signer, job)
	if err != nil {
		return err
	}
	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.URI, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// logoutToken signs a logout token for job (Back-Channel Logout 1.0 section
// 2.4). It carries no nonce — a relying party must reject one that does —
// and names the session by sid as well as the user by sub.
func (b *Backchannel) logoutToken(signer jose.Signer, job *store.BackchannelJob) (string, error) {
	jti, err := randomTokenID(16)
	if err != nil {
		return "", err
	}
	now := b.storage.store.Now()
	claims := &oidc.LogoutTokenClaims{
		Issuer:     b.issuer,
		Subject:    subjectOf(job.UserID),
		Audience:   oidc.Audience{job.ClientID},
		IssuedAt:   oidc.FromTime(now),
		Expiration: oidc.FromTime(now.Add(logoutTokenTTL)),
		JWTID:      jti,
		Events:     map[string]any{"http://schemas.openid.net/event/backchannel-logout": struct{}{}},
		SessionID:  job.SID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign logout token: %w", err)
	}
	return sig.CompactSerialize()
}

// logoutSigner is op.SignerFromKey with the typ header a logout token should
// carry, which lets a relying party tell it from an ID token.
func logoutSigner(key op.SigningKey) (jose.Signer, error) {
	return jose.NewSigner(jose.SigningKey{
		Algorithm: key.SignatureAlgorithm(),
		Key:       &jose.JSONWebKey{Key: key.Key(), KeyID: key.ID()},
	}, (&jose.SignerOptions{}).WithType("logout+jwt"))
}
