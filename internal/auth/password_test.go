package auth

import (
	"testing"
	"time"
)

// Password hashing waits for a free slot, so a burst of sign-ins cannot hold
// more than cap(argonSlots) argon2id working sets at once.
func TestPasswordHashingIsBounded(t *testing.T) {
	for range cap(argonSlots) {
		argonSlots <- struct{}{}
	}
	released := false
	release := func() {
		if !released {
			released = true
			for range cap(argonSlots) {
				<-argonSlots
			}
		}
	}
	defer release()

	done := make(chan error, 1)
	go func() {
		_, err := HashPassword("correct horse battery staple")
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("a hash was computed while every slot was taken")
	case <-time.After(200 * time.Millisecond):
	}

	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hashing did not resume after a slot was freed")
	}
}
