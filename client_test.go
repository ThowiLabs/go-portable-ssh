package portablessh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ThowiLabs/go-portable-ssh/sshtrust"
	"golang.org/x/crypto/ssh"
)

func testServer(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if conn.User() == "fixture" && string(pass) == "only-test" {
			return nil, nil
		}
		return nil, errors.New("rejected")
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			tcp, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer tcp.Close()
				server, channels, requests, err := ssh.NewServerConn(tcp, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for request := range requests {
							if request.Type != "exec" {
								_ = request.Reply(false, nil)
								continue
							}
							var payload struct{ Command string }
							if ssh.Unmarshal(request.Payload, &payload) != nil {
								_ = request.Reply(false, nil)
								return
							}
							_ = request.Reply(true, nil)
							status := uint32(0)
							if payload.Command == "hello" {
								_, _ = channel.Write([]byte("hola"))
							} else if payload.Command == "large-output" {
								_, _ = channel.Write(bytes.Repeat([]byte("x"), maxOutput+128))
							} else if payload.Command == "slow-command" {
								time.Sleep(250 * time.Millisecond)
							} else {
								status = 7
								_, _ = fmt.Fprint(channel.Stderr(), "failed")
							}
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), signer.PublicKey()
}

func TestDialRunAndVerifyPinnedHost(t *testing.T) {
	addr, serverKey := testServer(t)
	pin, err := sshtrust.Pinned(ssh.FingerprintSHA256(serverKey))
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Address: addr, User: "fixture", Auth: []ssh.AuthMethod{ssh.Password("only-test")}, HostKeyCallback: pin, Timeout: 2 * time.Second}
	client, err := Dial(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.Run(context.Background(), "hello")
	if err != nil || result.Stdout != "hola" || result.ExitCode != 0 || result.Truncated {
		t.Fatalf("successful command got %+v %v", result, err)
	}
	result, err = client.Run(context.Background(), "fail")
	if err != nil || result.ExitCode != 7 || result.Stderr != "failed" {
		t.Fatalf("failed command got %+v %v", result, err)
	}
	config.HostKeyCallback = sshtrust.Discover()
	if client, err := Dial(context.Background(), config); client != nil || err == nil {
		t.Fatalf("unknown host was connected without approval: %v", err)
	} else {
		var unknown *sshtrust.UnknownHostKeyError
		if !errors.As(err, &unknown) || unknown.Fingerprint != ssh.FingerprintSHA256(serverKey) {
			t.Fatalf("discovery error missing fingerprint: %v", err)
		}
	}
	config.HostKeyCallback, err = sshtrust.Pinned("SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if client, err := Dial(context.Background(), config); client != nil || err == nil {
		t.Fatalf("incorrect fingerprint accepted: %v", err)
	}
	config.HostKeyCallback = nil
	if client, err := Dial(context.Background(), config); client != nil || err == nil {
		t.Fatalf("missing verification callback accepted: %v", err)
	}
}

func TestDialCanceledBeforeConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := Dial(ctx, Config{Address: "127.0.0.1:12345", User: "fixture", Auth: []ssh.AuthMethod{ssh.Password("x")}, HostKeyCallback: sshtrust.Discover()})
	if client != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial got %v, %v", client, err)
	}
}
