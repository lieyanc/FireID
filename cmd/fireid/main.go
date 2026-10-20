package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/lieyanc/FireID/internal/api"
	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/config"
	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
	"github.com/lieyanc/FireID/internal/version"
	"github.com/lieyanc/FireID/web"
)

var logLevel = new(slog.LevelVar)

func setLogLevel(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err == nil {
		logLevel.Set(l)
	}
}

func main() {
	cfgPath := flag.String("c", "config.json", "path to config file (created or completed from the default template)")
	showVersion := flag.Bool("v", false, "print version and exit")
	resetAuth := flag.Bool("reset-auth", false, "enable account recovery, then exit; the next start prints a setup token that creates or resets a super administrator")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Fire ID %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildTime)
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	start := time.Now()
	cfgStore, state, err := config.Open(*cfgPath)
	if err != nil {
		slog.Error("configuration error", "configPath", *cfgPath, "err", err,
			"suggestion", "fix the file, or remove it to start with defaults")
		os.Exit(1)
	}
	if *resetAuth {
		if _, err := cfgStore.Update(func(c *config.Config) error { c.Auth.Recovery = true; return nil }); err != nil {
			fmt.Fprintln(os.Stderr, "reset failed:", err)
			os.Exit(1)
		}
		fmt.Println("Account recovery enabled. Restart Fire ID, open the web UI and enter the setup token it logs to create or reset a super administrator.")
		return
	}

	cfg := cfgStore.Get()
	setLogLevel(cfg.Logging.Level)
	switch state {
	case config.Created:
		slog.Info("no config file found, created one from the default template", "configPath", *cfgPath)
	case config.Completed:
		slog.Info("config file was missing fields, filled them in with defaults", "configPath", *cfgPath)
	}

	masterKey, err := cfgStore.MasterKey()
	if err != nil {
		slog.Error("failed to load the master key", "dataDir", cfgStore.DataDir(), "err", err)
		os.Exit(1)
	}
	box, err := secretbox.New(masterKey)
	if err != nil {
		slog.Error("failed to initialise the secret box", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfgStore.DataDir())
	if err != nil {
		slog.Error("failed to open the database", "dataDir", cfgStore.DataDir(), "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	publicBase := cfgStore.PublicBase()
	authSvc, err := auth.New(st, box, auth.Config{
		SessionTTL:                   time.Duration(cfg.Auth.SessionTTL) * time.Second,
		CookieDomain:                 cfg.Auth.CookieDomain,
		PasswordMinLength:            cfg.Auth.PasswordMinLength,
		RequireSecondFactorForAdmins: cfg.Auth.RequireSecondFactorForAdmins,
		SecureCookies:                cfg.Auth.Recovery == false && len(publicBase) > 8 && publicBase[:8] == "https://",
		Registration:                 cfg.Auth.Registration,
	}, slog.Default())
	if err != nil {
		slog.Error("failed to set up authentication", "err", err)
		os.Exit(1)
	}
	authSvc.SetIssuer(publicBase)

	slog.Info("configuration loaded", "version", version.Version, "configPath", *cfgPath,
		"dataDir", cfgStore.DataDir(), "issuer", publicBase)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Housekeeping: expired sessions and one-time tokens are removed on a
	// timer rather than by every request, so the hot path stays read-mostly.
	go housekeeping(ctx, st)

	srv, err := api.New(api.Deps{
		Store:             st,
		Auth:              authSvc,
		Config:            cfgStore,
		SecretBox:         box,
		Log:               slog.Default(),
		Web:               web.FS(),
		PublicBase:        publicBase,
		TrustProxyHeaders: true,
		Started:           start,
		SetLogLevel:       setLogLevel,
	})
	if err != nil {
		slog.Error("failed to build the API server", "err", err)
		os.Exit(1)
	}

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			cancel()
			if err := srv.Close(); err != nil {
				slog.Warn("closing the listener failed", "err", err)
			}
			slog.Info("shutdown complete")
		})
	}

	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	if err := srv.Start(addr); err != nil {
		slog.Error("failed to start the web UI / API server", "addr", addr, "err", err)
		os.Exit(1)
	}

	if tok := authSvc.SetupToken(); tok != "" {
		if cfg.Auth.Recovery {
			slog.Warn("account recovery enabled: open the web UI and enter this setup token to create or reset a super administrator",
				"url", publicBase, "setupToken", tok)
		} else {
			slog.Warn("no administrator account yet: open the web UI and enter this setup token",
				"url", publicBase, "setupToken", tok)
		}
	}
	if cfg.Email.Host == "" {
		slog.Warn("email is not configured: addresses cannot be verified and magic-link sign-in is unavailable")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	slog.Info("shutting down", "signal", s.String())
	shutdown()
}

// housekeeping deletes finished rows periodically. It stops when ctx is
// cancelled.
func housekeeping(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, job := range []struct {
				what string
				run  func() (int64, error)
			}{
				{"sessions", st.DeleteExpiredSessions},
				{"authorization requests", st.DeleteExpiredAuthRequests},
				{"authorization codes", st.DeleteExpiredAuthCodes},
				{"access tokens", st.DeleteExpiredAccessTokens},
				{"refresh tokens", st.DeleteExpiredRefreshTokens},
			} {
				if n, err := job.run(); err != nil {
					slog.Warn("could not delete expired "+job.what, "err", err)
				} else if n > 0 {
					slog.Debug("deleted expired "+job.what, "count", n)
				}
			}
		}
	}
}
