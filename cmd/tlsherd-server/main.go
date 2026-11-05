// Command tlsherd-server runs the TLS herd control plane: admin UI/API,
// agent API (separate listener) and background monitor worker.
//
// Configuration comes from TLSHERD_* environment variables (see
// internal/config). TLS is on by default; --insecure-http serves plain HTTP
// (for use behind a reverse proxy or by explicit operator choice).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kogonia/tlsherd/internal/config"
	"github.com/kogonia/tlsherd/internal/handler"
	"github.com/kogonia/tlsherd/internal/service"
	"github.com/kogonia/tlsherd/internal/store/postgres"
	"github.com/kogonia/tlsherd/internal/ui"
)

const (
	monitorTickInterval = time.Minute
	shutdownTimeout     = 15 * time.Second
)

func main() {
	insecure := flag.Bool("insecure-http", false, "serve plain HTTP instead of TLS")
	flag.Parse()

	if err := run(*insecure); err != nil {
		fmt.Fprintln(os.Stderr, "tlsherd-server:", err)
		os.Exit(1)
	}
}

func run(insecureFlag bool) error {
	getenv := func(key string) string {
		if insecureFlag && key == "TLSHERD_INSECURE_HTTP" {
			return "1"
		}
		return os.Getenv(key)
	}
	cfg, err := config.LoadServer(getenv)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	openCtx, cancelOpen := context.WithTimeout(ctx, 15*time.Second)
	st, err := postgres.Open(openCtx, cfg.DatabaseURL)
	cancelOpen()
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	svc := service.New(st, cfg.DataDir, logger)
	bootLogin := os.Getenv("TLSHERD_BOOTSTRAP_LOGIN")
	if err := svc.EnsureBootstrapAdmin(ctx, bootLogin); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	api := handler.New(svc, logger, handler.Options{
		SecureCookies: !cfg.InsecureHTTP,
		TrustProxy:    cfg.TrustProxy,
		UI:            ui.New(svc, logger),
	})

	adminSrv := newHTTPServer(cfg.AdminListen, api.AdminRoutes())
	agentSrv := newHTTPServer(cfg.AgentListen, api.AgentRoutes())

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		runMonitor(ctx, svc, logger)
	}()
	go func() {
		defer workers.Done()
		runNotifyWorker(ctx, svc, logger)
	}()

	serveErr := make(chan error, 2)
	go serve(cfg, adminSrv, "admin", logger, serveErr)
	go serve(cfg, agentSrv, "agent", logger, serveErr)

	select {
	case err := <-serveErr:
		stop()
		shutdownAll(ctx, adminSrv, agentSrv, logger)
		workers.Wait()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutting down", "component", "main")
	shutdownAll(ctx, adminSrv, agentSrv, logger)
	workers.Wait()
	return nil
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func serve(cfg config.ServerConfig, srv *http.Server, name string, logger *slog.Logger, errc chan<- error) {
	log := logger.With("component", "main", "listener", name, "addr", srv.Addr)
	if cfg.InsecureHTTP {
		log.Warn("serving plain HTTP")
		errc <- srv.ListenAndServe()
		return
	}
	log.Info("serving HTTPS")
	errc <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
}

func shutdownAll(parent context.Context, admin, agent *http.Server, logger *slog.Logger) {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), shutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range []*http.Server{admin, agent} {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if err := s.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("shutdown listener", "component", "main", "addr", s.Addr, "error", err)
			}
		}(srv)
	}
	wg.Wait()
}

// runMonitor drives the background worker until ctx is cancelled.
func runMonitor(ctx context.Context, svc *service.Services, logger *slog.Logger) {
	logger = logger.With("component", "monitor")
	t := time.NewTicker(monitorTickInterval)
	defer t.Stop()
	logger.Info("monitor worker started", "interval", monitorTickInterval.String())
	for {
		svc.MonitorTick(ctx)
		select {
		case <-ctx.Done():
			logger.Info("monitor worker stopped")
			return
		case <-t.C:
		}
	}
}

// runNotifyWorker delivers pending notification outbox rows.
func runNotifyWorker(ctx context.Context, svc *service.Services, logger *slog.Logger) {
	logger = logger.With("component", "notify")
	logger.Info("notification worker started")
	for {
		svc.ProcessNotificationOutbox(ctx)
		interval := svc.NotificationWorkerInterval(ctx)
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			logger.Info("notification worker stopped")
			return
		case <-t.C:
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
