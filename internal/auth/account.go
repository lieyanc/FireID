package auth

import "github.com/lieyanc/FireID/internal/store"

// ChangePassword sets a new password for a signed-in account. The current
// password is required when the account has one, with sign-in throttling. The
// session keepID stays signed in; every other session and every token issued
// to an application is revoked.
func (s *Service) ChangePassword(user *store.User, keepID int64, current, next, ip string) error {
	if user.PasswordHash != "" {
		if err := s.VerifyCurrentPassword(user, current, ip); err != nil {
			return err
		}
	}
	if err := s.checkPassword(next); err != nil {
		return err
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.store.ChangePassword(user.ID, hash, keepID); err != nil {
		return err
	}
	s.log.Info("password changed", "userId", user.ID)
	s.notifySecurityChange(user, changePasswordChanged)
	return nil
}
