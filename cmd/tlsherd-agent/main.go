// Command tlsherd-agent enrolls with a tlsherd server, polls for assigned
// certificates and installs them locally (backup, verify, restart, report).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kogonia/tlsherd/internal/agent"
	"github.com/kogonia/tlsherd/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tlsherd-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	once := flag.Bool("once", false, "run a single enroll/poll cycle and exit")
	dryRun := flag.Bool("dry-run", false, "validate and log planned actions without changing files, state or services")
	insecure := flag.Bool("insecure-skip-verify", false, "skip server TLS verification (lab use only)")
	flag.Parse()

	bs, err := config.LoadAgentBootstrap(os.Getenv)
	if err != nil {
		return err
	}
	bs.Once = bs.Once || *once
	bs.DryRun = bs.DryRun || *dryRun

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(bs.LogLevel)}))

	hc, err := agent.NewHTTPClient(bs.CAFile, *insecure)
	if err != nil {
		return err
	}
	if *insecure {
		logger.Warn("server TLS verification disabled", "component", "agent")
	}
	a, err := agent.New(agent.Options{Bootstrap: bs, Logger: logger, HTTPClient: hc})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
