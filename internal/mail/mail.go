// Package mail sends plain-text email through the configured SMTP relay. It
// uses only the standard library: implicit TLS on port 465, STARTTLS when
// asked for, and AUTH PLAIN, which net/smtp refuses to send over an
// unencrypted connection to anything but localhost.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/lieyanc/FireID/internal/config"
)

// timeout bounds one delivery, connection to QUIT.
const timeout = 30 * time.Second

// SMTP delivers through the relay in the current configuration, read on every
// send so a configuration change applies without a restart.
type SMTP struct {
	cfg func() config.EmailConfig
}

// NewSMTP returns a sender that reads its settings from cfg.
func NewSMTP(cfg func() config.EmailConfig) *SMTP { return &SMTP{cfg: cfg} }

// Enabled reports whether a relay is configured.
func (m *SMTP) Enabled() bool { return m.cfg().Host != "" }

// Send delivers one plain-text message.
func (m *SMTP) Send(ctx context.Context, to, subject, body string) error {
	c := m.cfg()
	if c.Host == "" {
		return errors.New("email is not configured")
	}
	msg, err := Compose(c.FromName, c.FromEmail, to, subject, body, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return deliver(ctx, c, to, msg)
}

// Compose builds the RFC 5322 message. Every header value is either a parsed
// address or MIME-encoded, so no caller-supplied text can start a new header.
func Compose(fromName, fromEmail, to, subject, body string, now time.Time) ([]byte, error) {
	from, err := mail.ParseAddress(fromEmail)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}
	from.Name = fromName
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient address: %w", err)
	}
	if strings.ContainsAny(subject, "\r\n") {
		return nil, errors.New("subject contains a line break")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]

	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from.String())
	header("To", rcpt.String())
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", `text/plain; charset="utf-8"`)
	header("Content-Transfer-Encoding", "quoted-printable")
	// Sign-in mail is not a newsletter; ask auto-responders to stay quiet.
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func deliver(ctx context.Context, c config.EmailConfig, to string, msg []byte) error {
	port := c.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.Insecure} //nolint:gosec // opt-in for a local relay

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: timeout}
	if port == 465 {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer client.Close()

	if port != 465 && c.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("the relay does not offer STARTTLS")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if c.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	from, err := mail.ParseAddress(c.FromEmail)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(rcpt.Address); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end of data: %w", err)
	}
	return client.Quit()
}
