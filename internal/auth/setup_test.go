package auth

import (
	"errors"
	"sync"
	"testing"
)

// Two setup attempts racing on the same token must not both get through:
// the first holds the setup until it finishes, and the second then finds the
// token spent.
func TestBeginSetupIsExclusive(t *testing.T) {
	s := &Service{setup: "tok"}

	if _, err := s.BeginSetup("wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong token: %v", err)
	}

	// A failed attempt leaves the token usable.
	done, err := s.BeginSetup("tok")
	if err != nil {
		t.Fatal(err)
	}
	done(false)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done, err := s.BeginSetup("tok")
			if err != nil {
				if !errors.Is(err, ErrSetupUnavailable) {
					t.Errorf("concurrent attempt: %v", err)
				}
				return
			}
			mu.Lock()
			granted++
			mu.Unlock()
			done(true)
		}()
	}
	wg.Wait()
	if granted != 1 {
		t.Fatalf("%d attempts were granted the setup token, want 1", granted)
	}
	if s.SetupToken() != "" {
		t.Fatal("token still active after a successful setup")
	}
}
