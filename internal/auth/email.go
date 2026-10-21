package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/lieyanc/FireID/internal/store"
)

// EmailLoginTTL is how long an emailed sign-in link and code stay valid.
const EmailLoginTTL = 10 * time.Minute

// Mailer delivers plain-text email. *mail.SMTP implements it.
type Mailer interface {
	Enabled() bool
	Send(ctx context.Context, to, subject, body string) error
}

// ErrEmailUnavailable is returned when no SMTP relay is configured.
var ErrEmailUnavailable = errors.New("email sign-in is not available")

// SetMailer installs the email sender.
func (s *Service) SetMailer(m Mailer) { s.mailer = m }

// EmailEnabled reports whether email sign-in can be offered.
func (s *Service) EmailEnabled() bool { return s.mailer != nil && s.mailer.Enabled() }

// WaitForMail blocks until every delivery started so far has finished. Tests
// and shutdown use it.
func (s *Service) WaitForMail() { s.mailWG.Wait() }

// StartEmailLogin sends a sign-in link and code to email if it belongs to an
// account that may sign in. The caller learns nothing either way: the lookup,
// the token and the delivery all happen after this returns, so neither the
// answer nor its timing depends on whether the address is known. authReqID is
// carried in the link so a sign-in started from an app returns to it; lang
// picks the message language ("zh" or anything else for English).
func (s *Service) StartEmailLogin(email, authReqID, ip, lang string) error {
	if !s.EmailEnabled() {
		return ErrEmailUnavailable
	}
	email = store.NormaliseEmail(email)
	if err := store.ValidateEmail(email); err != nil {
		return err
	}
	if wait := s.mailIP.RetryAfter("ip:" + ip); wait > 0 {
		return &RateLimitError{RetryAfter: wait}
	}
	if wait := s.mailAddr.RetryAfter("addr:" + email); wait > 0 {
		return &RateLimitError{RetryAfter: wait}
	}
	// Every request counts, successful or not: the limit is on mail sent.
	s.mailIP.Fail("ip:" + ip)
	s.mailAddr.Fail("addr:" + email)

	s.mailWG.Add(1)
	go func() {
		defer s.mailWG.Done()
		if err := s.sendEmailLogin(email, authReqID, ip, lang); err != nil {
			s.log.Warn("could not send a sign-in email", "err", err)
		}
	}()
	return nil
}

func (s *Service) sendEmailLogin(email, authReqID, ip, lang string) error {
	user, err := s.store.UserByEmail(email)
	if errors.Is(err, store.ErrNotFound) {
		s.log.Info("sign-in email requested for an unknown address", "ip", ip)
		return nil
	}
	if err != nil {
		return err
	}
	if user.Status == store.UserDisabled {
		s.log.Info("sign-in email requested for a disabled account", "userId", user.ID, "ip", ip)
		return nil
	}
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	code, err := randomDigits(6)
	if err != nil {
		return err
	}
	if err := s.store.CreateCredentialToken(user.ID, store.PurposeEmailLogin, user.Email,
		store.HashToken(token), store.HashToken(code), ip, EmailLoginTTL); err != nil {
		return err
	}

	// The token rides in the fragment, which browsers never send to a server,
	// so it stays out of access logs and Referer headers.
	frag := url.Values{"token": {token}}
	if authReqID != "" && len(authReqID) <= 128 {
		frag.Set("auth_req_id", authReqID)
	}
	link := s.issuer + "/email-login#" + frag.Encode()
	subject, body := emailLoginMessage(lang, code, link)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.mailer.Send(ctx, user.Email, subject, body); err != nil {
		return fmt.Errorf("deliver to user %d: %w", user.ID, err)
	}
	s.log.Info("sign-in email sent", "userId", user.ID, "ip", ip)
	return nil
}

func emailLoginMessage(lang, code, link string) (subject, body string) {
	minutes := int(EmailLoginTTL.Minutes())
	if strings.HasPrefix(strings.ToLower(lang), "zh") {
		return "Fire ID 登录验证码：" + code, fmt.Sprintf(
			"你的登录验证码是：\n\n    %s\n\n也可以打开下面的链接登录：\n\n%s\n\n"+
				"验证码和链接在 %d 分钟内有效，只能使用一次。\n"+
				"如果不是你本人在登录，忽略这封邮件即可，你的账号不会有任何变化。\n",
			code, link, minutes)
	}
	return "Your Fire ID sign-in code: " + code, fmt.Sprintf(
		"Your sign-in code is:\n\n    %s\n\nOr open this link to sign in:\n\n%s\n\n"+
			"The code and the link work once and expire in %d minutes.\n"+
			"If you did not try to sign in, ignore this email; nothing about your account changes.\n",
		code, link, minutes)
}

// EmailLoginProof is what the person sends back: the token from the link, or
// the address and the code they typed.
type EmailLoginProof struct {
	Token string
	Email string
	Code  string
	// TOTP is the second factor, required when the account has one.
	TOTP string
}

// FinishEmailLogin redeems an emailed link or code. When the account also
// needs a second factor and none was sent, it returns a SecondFactorError
// without spending the token, so the person can add the code and retry.
// Proving control of the address activates a pending account.
func (s *Service) FinishEmailLogin(p EmailLoginProof, ip string) (*LoginResult, error) {
	if wait := s.login.RetryAfter("email:" + ip); wait > 0 {
		return nil, &RateLimitError{RetryAfter: wait}
	}
	tok, err := s.findEmailToken(p)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			s.login.Fail("email:" + ip)
		}
		return nil, err
	}
	user, err := s.store.UserByID(tok.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status == store.UserDisabled || !strings.EqualFold(user.Email, tok.Email) {
		// Disabled since the mail went out, or the address changed: the
		// mailbox no longer speaks for this account.
		return nil, ErrInvalidCredentials
	}

	res := &LoginResult{User: user, AMR: "email", ACR: store.ACRLoA1}
	// needsSecondFactor is not used here: it answers for active accounts
	// only, and this sign-in may be what activates a pending one.
	if user.TOTPConfirmed || s.PolicyRequiresTOTP(user) {
		if !user.TOTPConfirmed {
			// Enrolment needs the password; email alone cannot set it up.
			return nil, &SecondFactorError{User: user, Enrol: true}
		}
		if strings.TrimSpace(p.TOTP) == "" {
			return nil, &SecondFactorError{User: user}
		}
		if err := s.checkSecondFactor(user, p.TOTP, ip); err != nil {
			return nil, err
		}
		res.AMR, res.ACR = "email otp", store.ACRLoA2
	}

	if err := s.store.ConsumeCredentialToken(tok.ID); err != nil {
		if errors.Is(err, store.ErrConsumed) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	s.login.Reset("email:" + ip)
	if user.Status == store.UserPending {
		if err := s.store.ActivateUser(user.ID); err != nil {
			return nil, err
		}
		user.Status = store.UserActive
		s.log.Info("email address verified by sign-in", "userId", user.ID)
	}
	return res, nil
}

// findEmailToken resolves the proof to a live token. Every typed code, right
// or wrong, uses one of the token's attempts; a wrong one also counts against
// the source address.
func (s *Service) findEmailToken(p EmailLoginProof) (*store.CredentialToken, error) {
	if p.Token != "" {
		tok, err := s.store.CredentialTokenByHash(store.PurposeEmailLogin, store.HashToken(p.Token))
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return tok, err
	}
	code := strings.TrimSpace(p.Code)
	if p.Email == "" || code == "" {
		return nil, ErrInvalidCredentials
	}
	tok, err := s.store.LatestCredentialToken(store.PurposeEmailLogin, p.Email)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := s.store.ReserveCodeAttempt(tok.ID); err != nil {
		if errors.Is(err, store.ErrConsumed) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(store.HashToken(code)), []byte(tok.CodeHash)) != 1 {
		if err := s.store.SpendIfExhausted(tok.ID); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	return tok, nil
}

// randomDigits returns n uniformly random decimal digits.
func randomDigits(n int) (string, error) {
	var b strings.Builder
	for range n {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("generate code: %w", err)
		}
		b.WriteByte(byte('0' + d.Int64()))
	}
	return b.String(), nil
}

// Security changes an account holder is told about by email.
const (
	changeTOTPOn = iota
	changeTOTPOff
	changeRecoveryCodes
	changePasskeyAdded
	changePasskeyRemoved
	changePasswordChanged
)

// notifySecurityChange emails the account about a change to how it signs in,
// so a person whose password was used by someone else finds out.
// Nothing is sent when email is not configured or the address is unverified.
func (s *Service) notifySecurityChange(user *store.User, change int) {
	if !s.EmailEnabled() || user.Status != store.UserActive {
		return
	}
	var en, zh string
	switch change {
	case changeTOTPOn:
		en, zh = "Two-step verification was turned on", "两步验证已开启"
	case changeTOTPOff:
		en, zh = "Two-step verification was turned off", "两步验证已关闭"
	case changeRecoveryCodes:
		en, zh = "New recovery codes were generated; the old ones no longer work", "已生成新的恢复码，旧恢复码已失效"
	case changePasskeyAdded:
		en, zh = "A passkey was added", "已添加通行密钥"
	case changePasskeyRemoved:
		en, zh = "A passkey was removed", "已移除通行密钥"
	case changePasswordChanged:
		en, zh = "Your password was changed", "密码已修改"
	default:
		return
	}
	at := s.now().Format("2006-01-02 15:04 MST")
	subject := "Fire ID: " + en
	body := fmt.Sprintf("%s for %s at %s.\n"+
		"If this was not you, sign in at %s, change your password and review two-step verification,\n"+
		"or contact your administrator.\n\n"+
		"%s（账号 %s，时间 %s）。\n如果不是你本人操作，请登录 %s 修改密码并检查两步验证，或联系管理员。\n",
		en, user.Username, at, s.issuer, zh, user.Username, at, s.issuer)
	to := user.Email
	s.mailWG.Add(1)
	go func() {
		defer s.mailWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.mailer.Send(ctx, to, subject, body); err != nil {
			s.log.Warn("could not send a security notice", "userId", user.ID, "err", err)
		}
	}()
}

// NotifyAccessDecision tells a user that their request to use an app was
// approved or denied. Like the security notices it is best effort: nothing is
// sent without SMTP or to an unverified address.
func (s *Service) NotifyAccessDecision(user *store.User, appName string, approved bool) {
	if !s.EmailEnabled() || user.Status != store.UserActive {
		return
	}
	// The name is owner-supplied and goes into a header.
	appName = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, appName)
	en, zh := "approved", "已通过"
	if !approved {
		en, zh = "denied", "未通过"
	}
	subject := fmt.Sprintf("Fire ID: your request to use %s was %s", appName, en)
	body := fmt.Sprintf("Your request to use %s was %s.\n", appName, en)
	if approved {
		body += "You can now sign in to it with your Fire ID account.\n"
	}
	body += fmt.Sprintf("\n你申请使用 %s 的请求%s。\n", appName, zh)
	if approved {
		body += "现在可以用 Fire ID 账号登录它了。\n"
	}
	to := user.Email
	s.mailWG.Add(1)
	go func() {
		defer s.mailWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.mailer.Send(ctx, to, subject, body); err != nil {
			s.log.Warn("could not send an access decision", "userId", user.ID, "err", err)
		}
	}()
}
