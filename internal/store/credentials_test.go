package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCodeAttemptBudgetHoldsUnderConcurrency(t *testing.T) {
	f := newOIDCFixture(t)
	if err := f.st.CreateCredentialToken(f.user.ID, PurposeEmailLogin, f.user.Email,
		"token-hash", "code-hash", "192.0.2.1", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	tok, err := f.st.LatestCredentialToken(PurposeEmailLogin, f.user.Email)
	if err != nil {
		t.Fatal(err)
	}

	const guesses = 4 * MaxCodeAttempts
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for range guesses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f.st.ReserveCodeAttempt(tok.ID); err == nil {
				mu.Lock()
				granted++
				mu.Unlock()
			} else if !errors.Is(err, ErrConsumed) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if granted != MaxCodeAttempts {
		t.Fatalf("%d of %d parallel guesses got an attempt, want %d", granted, guesses, MaxCodeAttempts)
	}
	if err := f.st.SpendIfExhausted(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CredentialTokenByHash(PurposeEmailLogin, "token-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link after the attempts ran out: got %v, want ErrNotFound", err)
	}
}

func TestConfirmTOTPBindsToTheVerifiedSecret(t *testing.T) {
	f := newOIDCFixture(t)
	if err := f.st.BeginTOTPEnrolment(f.user.ID, "secret-1"); err != nil {
		t.Fatal(err)
	}
	// A second tab restarts the enrolment after the first one read secret-1.
	if err := f.st.BeginTOTPEnrolment(f.user.ID, "secret-2"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.ConfirmTOTP(f.user.ID, "secret-1", 100, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("confirming a replaced secret: got %v, want ErrConflict", err)
	}
	if err := f.st.ConfirmTOTP(f.user.ID, "secret-2", 100, []string{"h1"}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.BeginTOTPEnrolment(f.user.ID, "secret-3"); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-enrolling over a confirmed secret: got %v, want ErrConflict", err)
	}
	if err := f.st.AcceptTOTPStep(f.user.ID, 100); !errors.Is(err, ErrConsumed) {
		t.Fatalf("the confirming step again: got %v, want ErrConsumed", err)
	}
}
