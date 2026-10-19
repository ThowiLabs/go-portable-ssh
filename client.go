package portablessh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultTimeout = 20 * time.Second
const maxOutput = 4 << 20

type Config struct {
	Address         string
	User            string
	Auth            []ssh.AuthMethod
	HostKeyCallback ssh.HostKeyCallback
	Timeout         time.Duration
}

type Client struct {
	conn *ssh.Client
}

type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// Dial limits TCP connection and SSH handshake to the same deadline.
// A host-key callback is mandatory, so host verification cannot be skipped accidentally.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Address == "" || cfg.User == "" || len(cfg.Auth) == 0 || cfg.HostKeyCallback == nil {
		return nil, errors.New("SSH address, user, authentication and host verification are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	network := &net.Dialer{}
	tcp, err := network.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("connect SSH: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := tcp.SetDeadline(deadline); err != nil {
			_ = tcp.Close()
			return nil, err
		}
	}
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = tcp.Close()
		case <-done:
		}
	}()
	connection, channels, requests, err := ssh.NewClientConn(tcp, cfg.Address, &ssh.ClientConfig{
		User: cfg.User, Auth: cfg.Auth, HostKeyCallback: cfg.HostKeyCallback, Timeout: cfg.Timeout,
	})
	close(done)
	<-watcherDone
	if err != nil {
		_ = tcp.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("handshake SSH: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := tcp.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &Client{conn: ssh.NewClient(connection, channels, requests)}, nil
}

func (c *Client) Raw() *ssh.Client {
	return c.conn
}

func (c *Client) Close() error {
	return c.conn.Close()
}

type outputBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	received := len(p)
	remaining := maxOutput - b.buffer.Len()
	if remaining < len(p) {
		b.truncated = true
		if remaining < 0 {
			remaining = 0
		}
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return received, nil
}

func (b *outputBuffer) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String(), b.truncated
}

// Run executes a single remote command; nonzero exit statuses return in Result.
// Sessions are independent, so multiple commands can run concurrently.
func (c *Client) Run(ctx context.Context, command string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	session, err := c.conn.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer session.Close()
	var out, stderr outputBuffer
	session.Stdout = &out
	session.Stderr = &stderr
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return Result{}, ctx.Err()
	case err := <-done:
		stdout, truncatedOut := out.snapshot()
		stderrText, truncatedErr := stderr.snapshot()
		result := Result{Stdout: stdout, Stderr: stderrText, ExitCode: 0, Truncated: truncatedOut || truncatedErr}
		if err == nil {
			return result, nil
		}
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			result.ExitCode = exit.ExitStatus()
			return result, nil
		}
		return result, err
	}
}
