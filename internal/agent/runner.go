package agent

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// Clock abstracts time for tests.
type Clock interface{ Now() time.Time }

// Runner executes external commands as argv (never through a shell).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// SystemClock is the real wall clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	return out.String(), errb.String(), err
}
