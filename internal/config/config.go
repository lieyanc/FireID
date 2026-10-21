// Package config defines the on-disk configuration and a Store that
// serializes mutations and persists them atomically.
package config

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// templateFS holds the complete default configuration. It is written out when
// no config file exists and fills in fields missing from an existing one.
//
//go:embed template.json
var templateFS embed.FS

// State reports what Open had to do to the configuration file.
type State int

const (
	// Loaded means the file existed and was complete.
	Loaded State = iota
	// Created means no file existed and one was written from the template.
	Created
	// Completed means the file existed but was missing fields, which were filled in.
	Completed
)

// Config is the whole on-disk configuration.
type Config struct {
	Server  ServerConfig  `json:"server"`
	Auth    AuthConfig    `json:"auth"`
	OIDC    OIDCConfig    `json:"oidc"`
	Email   EmailConfig   `json:"email"`
	Logging LoggingConfig `json:"logging"`
	Update  UpdateConfig  `json:"update"`
	DataDir string        `json:"dataDir"`
}

// ServerConfig is the listener and the externally visible base URL.
type ServerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// PublicURL is the externally reachable base URL of this instance. It is the
	// OIDC issuer, so changing it invalidates every issued token and every
	// registered redirect URI.
	PublicURL string `json:"publicUrl"`
	// TrustProxyHeaders honours X-Forwarded-For and X-Forwarded-Proto. Enable
	// it only when a reverse proxy is the sole way to reach the listener;
	// otherwise any client can pick the address its sign-in attempts are
	// throttled under.
	TrustProxyHeaders bool `json:"trustProxyHeaders"`
}

// AuthConfig holds session and login-policy settings. Secrets live in the data
// directory, not here.
type AuthConfig struct {
	SessionTTL int `json:"sessionTtl"` // seconds
	// CookieDomain lets the session cookie be shared with application
	// subdomains. Empty means host-only.
	CookieDomain string `json:"cookieDomain,omitempty"`
	// Registration is the deployment-wide policy: "closed" (only invitations),
	// "open" (anyone may register; new accounts need email verification when
	// SMTP is configured). Per-app policy is stored in the database.
	Registration string `json:"registration"`
	// PasswordMinLength applies to password creation and changes.
	PasswordMinLength int `json:"passwordMinLength"`
	// RequireSecondFactor forces a second factor for super admins.
	RequireSecondFactorForAdmins bool `json:"requireSecondFactorForAdmins"`
	// Recovery lets the setup token create or reset a super admin (set by
	// -reset-auth, cleared once used).
	Recovery bool `json:"recovery,omitempty"`
}

// OIDCConfig holds provider-level defaults.
type OIDCConfig struct {
	// SigningAlgorithm is the algorithm of the current signing key:
	// "RS256" or "ES256".
	SigningAlgorithm string `json:"signingAlgorithm"`
	// IDTokenTTL and AccessTokenTTL are lifetimes in seconds.
	IDTokenTTL     int `json:"idTokenTtl"`
	AccessTokenTTL int `json:"accessTokenTtl"`
	// CodeTTL is the authorization-code lifetime in seconds. RFC 9700 suggests
	// keeping it short; 60 is the maximum this provider will accept.
	CodeTTL int `json:"codeTtl"`
	// RefreshTokenTTL is the absolute lifetime of a refresh-token family.
	RefreshTokenTTL int `json:"refreshTokenTtl"`
	// DisableDeviceFlow removes the device authorization endpoint entirely.
	DisableDeviceFlow bool `json:"disableDeviceFlow"`
}

// EmailConfig describes the SMTP relay used for verification, magic links and
// notifications. An empty Host disables every email feature: accounts then
// cannot verify their address and magic-link sign-in is unavailable.
type EmailConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"`
	FromName  string `json:"fromName"`
	FromEmail string `json:"fromEmail"`
	// StartTLS upgrades a plaintext connection with STARTTLS. Implicit TLS is
	// used when Port is 465.
	StartTLS bool `json:"startTls"`
	// Insecure skips certificate verification. Only for a local relay.
	Insecure bool `json:"insecure,omitempty"`
}

// LoggingConfig mirrors the house convention.
type LoggingConfig struct {
	Level string `json:"level"`
}

// UpdateConfig is the self-update block shared by the Fire* projects.
type UpdateConfig struct {
	Enabled       bool   `json:"enabled"`
	Channel       string `json:"channel"`
	CheckInterval int    `json:"checkInterval"`
	Source        string `json:"source"`
	ProxyBaseURL  string `json:"proxyBaseUrl"`
	Repo          string `json:"repo"`
}

// Store owns the configuration file: it serializes mutations and writes them
// atomically.
type Store struct {
	path    string
	dataDir string

	mu  sync.RWMutex
	cfg Config
}

// Open reads the configuration at path, creating it from the template when it is
// absent and filling in missing fields when it is incomplete.
func Open(path string) (*Store, State, error) {
	if path == "" {
		path = "config.json"
	}
	state := Loaded

	defaults, err := defaultsFromTemplate()
	if err != nil {
		return nil, state, err
	}

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		state = Created
		raw = nil
	case err != nil:
		return nil, state, fmt.Errorf("read config: %w", err)
	default:
		// The file may hold the SMTP password.
		ownerOnly(path)
	}

	cfg := defaults
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, state, fmt.Errorf("parse config: %w", err)
		}
		if missing, err := fillMissing(raw, &cfg, defaults); err != nil {
			return nil, state, err
		} else if missing {
			state = Completed
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, state, err
	}

	s := &Store{path: path, cfg: cfg}
	s.dataDir = s.resolveDataDir()

	if state != Loaded {
		if err := s.write(); err != nil {
			return nil, state, err
		}
	}
	return s, state, nil
}

// defaultsFromTemplate decodes the embedded template.
func defaultsFromTemplate() (Config, error) {
	var cfg Config
	raw, err := templateFS.ReadFile("template.json")
	if err != nil {
		return cfg, fmt.Errorf("read config template: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config template: %w", err)
	}
	return cfg, nil
}

// fillMissing writes default values into fields the file did not mention.
// It works on the raw JSON rather than the decoded struct so that an explicit
// false or 0 is preserved.
func fillMissing(raw []byte, cfg *Config, defaults Config) (bool, error) {
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return false, fmt.Errorf("parse config: %w", err)
	}

	missing := false
	merged := map[string]any{}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(cfgBytes, &merged); err != nil {
		return false, err
	}
	defBytes, err := json.Marshal(defaults)
	if err != nil {
		return false, err
	}
	var defMerged map[string]any
	if err := json.Unmarshal(defBytes, &defMerged); err != nil {
		return false, err
	}

	for key, defVal := range defMerged {
		cur, ok := merged[key]
		if !ok {
			cur = map[string]any{}
		}
		curMap, curIsMap := cur.(map[string]any)
		defMap, defIsMap := defVal.(map[string]any)
		if curIsMap && defIsMap {
			if _, existed := present[key]; !existed {
				missing = true
			}
			for k, v := range defMap {
				if _, ok := curMap[k]; !ok {
					curMap[k] = v
					missing = true
				}
			}
			merged[key] = curMap
			continue
		}
		if _, existed := present[key]; !existed {
			merged[key] = defVal
			missing = true
		}
	}

	out, err := json.Marshal(merged)
	if err != nil {
		return false, err
	}
	*cfg = Config{}
	if err := json.Unmarshal(out, cfg); err != nil {
		return false, err
	}
	return missing, nil
}

// validate rejects configurations that cannot work.
func (c *Config) validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}
	if c.Server.PublicURL == "" {
		return errors.New("server.publicUrl is required: it is the OIDC issuer and must be the URL clients reach this instance on")
	}
	if !strings.HasPrefix(c.Server.PublicURL, "http://") && !strings.HasPrefix(c.Server.PublicURL, "https://") {
		return fmt.Errorf("server.publicUrl must start with http:// or https://, got %q", c.Server.PublicURL)
	}
	if strings.HasSuffix(c.Server.PublicURL, "/") {
		return errors.New("server.publicUrl must not end with a slash")
	}
	switch c.OIDC.SigningAlgorithm {
	case "RS256", "ES256":
	default:
		return fmt.Errorf("oidc.signingAlgorithm must be RS256 or ES256, got %q", c.OIDC.SigningAlgorithm)
	}
	switch c.Auth.Registration {
	case "closed", "open":
	default:
		return fmt.Errorf("auth.registration must be closed or open, got %q", c.Auth.Registration)
	}
	if c.Auth.PasswordMinLength < 8 {
		return fmt.Errorf("auth.passwordMinLength must be at least 8, got %d", c.Auth.PasswordMinLength)
	}
	if c.OIDC.CodeTTL < 10 || c.OIDC.CodeTTL > 60 {
		return fmt.Errorf("oidc.codeTtl must be between 10 and 60 seconds, got %d", c.OIDC.CodeTTL)
	}
	if c.Email.Host != "" && c.Email.FromEmail == "" {
		return errors.New("email.fromEmail is required when email.host is set")
	}
	return nil
}

// Get returns a copy of the current configuration.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Path is the configuration file location.
func (s *Store) Path() string { return s.path }

// DataDir is the directory holding the database and key material.
func (s *Store) DataDir() string { return s.dataDir }

// PublicBase is the externally reachable base URL without a trailing slash.
func (s *Store) PublicBase() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSuffix(s.cfg.Server.PublicURL, "/")
}

// Issuer is the OIDC issuer identifier, which is the public base URL.
func (s *Store) Issuer() string { return s.PublicBase() }

// Update applies fn to the configuration and persists the result. On error the
// in-memory value is left untouched.
func (s *Store) Update(fn func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	if err := fn(&next); err != nil {
		return s.cfg, err
	}
	if err := next.validate(); err != nil {
		return s.cfg, err
	}
	prev, prevDir := s.cfg, s.dataDir
	s.cfg, s.dataDir = next, s.resolveDataDirLocked(next)
	if err := s.writeLocked(); err != nil {
		s.cfg, s.dataDir = prev, prevDir
		return s.cfg, err
	}
	return s.cfg, nil
}

// resolveDataDir computes the absolute data directory.
func (s *Store) resolveDataDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolveDataDirLocked(s.cfg)
}

func (s *Store) resolveDataDirLocked(c Config) string {
	dir := c.DataDir
	if dir == "" {
		dir = "./data"
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	base := filepath.Dir(s.path)
	return filepath.Clean(filepath.Join(base, dir))
}

// write persists the current configuration.
func (s *Store) write() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeLocked()
}

// writeLocked writes the configuration atomically, owner-readable only.
func (s *Store) writeLocked() error {
	out, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	out = append(out, '\n')

	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// MasterKey returns the 32-byte key used to encrypt secrets at rest, creating
// it on first use. The key file lives in the data directory with mode 0600 and
// is never written to the configuration file.
func (s *Store) MasterKey() ([]byte, error) {
	path := filepath.Join(s.dataDir, "master.key")
	if raw, err := os.ReadFile(path); err == nil {
		ownerOnly(path)
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("decode master key: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("master key is %d bytes, expected 32", len(key))
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read master key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	// O_EXCL: a key that appeared since the read above belongs to another
	// process and must not be replaced, or what it sealed becomes unreadable.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return s.MasterKey()
	}
	if err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if _, err := f.WriteString(encoded + "\n"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return key, nil
}

// ownerOnly removes group and other access from a file that holds a secret.
// It is best effort: a read-only mount, where the operator controls the mode,
// must not stop the service from starting.
func ownerOnly(path string) {
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, info.Mode().Perm()&0o700)
	}
}
