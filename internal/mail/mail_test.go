package mail

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lieyanc/FireID/internal/config"
)

func TestComposeRefusesHeaderInjection(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, subject string
	}{
		{"line break in subject", "id@example.com", "a@example.com", "hi\r\nBcc: x@evil.example"},
		{"line break in recipient", "id@example.com", "a@example.com\r\nBcc: x@evil.example", "hi"},
		{"two recipients", "id@example.com", "a@example.com, b@example.com", "hi"},
		{"bad sender", "not an address", "a@example.com", "hi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compose("Fire ID", tc.from, tc.to, tc.subject, "body", time.Now()); err == nil {
				t.Fatal("composed a message it should have refused")
			}
		})
	}
}

func TestComposeRoundTrip(t *testing.T) {
	body := "你的登录验证码是：\n\n    123456\n\nhttps://id.example.com/email-login#token=" + strings.Repeat("x", 80) + "\n"
	raw, err := Compose("Fire ID", "id@example.com", "Alice <alice@example.com>", "Fire ID 登录验证码：123456", body,
		time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != "Fire ID 登录验证码：123456" {
		t.Fatalf("subject %q (%v)", subject, err)
	}
	if to, err := msg.Header.AddressList("To"); err != nil || len(to) != 1 || to[0].Address != "alice@example.com" {
		t.Fatalf("to %v (%v)", to, err)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(string(decoded), "\r\n", "\n"); got != body {
		t.Fatalf("body changed in transit:\n%q\nwant\n%q", got, body)
	}
}

// fakeRelay is a minimal SMTP server that accepts one message.
func fakeRelay(t *testing.T) (addr string, got <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		say("220 relay ready")
		var data strings.Builder
		var envelope []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-relay")
				say("250 8BITMIME")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				envelope = append(envelope, strings.TrimSpace(line))
				say("250 ok")
			case cmd == "DATA":
				say("354 go ahead")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				out <- strings.Join(envelope, "\n") + "\n\n" + data.String()
				return
			default:
				say("502 not implemented")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestSendThroughRelay(t *testing.T) {
	addr, got := fakeRelay(t)
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	m := NewSMTP(func() config.EmailConfig {
		return config.EmailConfig{Host: host, Port: p, FromName: "Fire ID", FromEmail: "id@example.com"}
	})
	if !m.Enabled() {
		t.Fatal("relay configured but not enabled")
	}
	if err := m.Send(context.Background(), "alice@example.com", "Hello", "code 123456\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case transcript := <-got:
		for _, want := range []string{"MAIL FROM:<id@example.com>", "RCPT TO:<alice@example.com>", "Subject: Hello", "code 123456"} {
			if !strings.Contains(transcript, want) {
				t.Errorf("relay did not see %q in:\n%s", want, transcript)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay received nothing")
	}
}
