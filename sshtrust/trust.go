package sshtrust

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

type UnknownHostKeyError struct {
	Host        string
	Algorithm   string
	Fingerprint string
}

func (e *UnknownHostKeyError) Error() string {
	return fmt.Sprintf("unknown SSH host key for %s: %s", e.Host, e.Fingerprint)
}

type HostKeyMismatchError struct {
	Host     string
	Expected string
	Actual   string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("SSH host key mismatch for %s: expected %s, got %s", e.Host, e.Expected, e.Actual)
}

func ValidFingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	bytes, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(bytes) == 32 && base64.RawStdEncoding.EncodeToString(bytes) == strings.TrimPrefix(value, "SHA256:")
}

// Discover reports the presented key without accepting the handshake.
// Its fingerprint must be independently confirmed before retrying with Pinned.
func Discover() ssh.HostKeyCallback {
	return func(host string, _ net.Addr, key ssh.PublicKey) error {
		return &UnknownHostKeyError{Host: host, Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
	}
}

func Pinned(fingerprint string) (ssh.HostKeyCallback, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, errors.New("invalid SSH host key fingerprint")
	}
	return func(host string, _ net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(actual)) != 1 {
			return &HostKeyMismatchError{Host: host, Expected: fingerprint, Actual: actual}
		}
		return nil
	}, nil
}
