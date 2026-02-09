// Package execx provides an abstraction over os/exec for testability.
package execx

import (
	"bytes"
	"context"
	"os/exec"
)

// Runner executes external commands.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) (stdout, stderr []byte, err error)
}

// RealRunner executes commands via os/exec.
type RealRunner struct{}

func (RealRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), err
}
