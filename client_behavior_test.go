package portablessh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ThowiLabs/go-portable-ssh/sshtrust"
	"golang.org/x/crypto/ssh"
)

func TestOutputLimitAndCanceledCommand(t *testing.T) {
	address, key := testServer(t)
	callback, err := sshtrust.Pinned(ssh.FingerprintSHA256(key))
	if err != nil {
		t.Fatal(err)
	}
	client, err := Dial(context.Background(), Config{
		Address: address, User: "fixture",
		Auth:            []ssh.AuthMethod{ssh.Password("only-test")},
		HostKeyCallback: callback, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	result, err := client.Run(context.Background(), "large-output")
	if err != nil || len(result.Stdout) != maxOutput || !result.Truncated || result.ExitCode != 0 {
		t.Fatalf("output was not bounded: len=%d truncated=%t status=%d err=%v", len(result.Stdout), result.Truncated, result.ExitCode, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = client.Run(ctx, "slow-command")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled command continued: %v", err)
	}
}
