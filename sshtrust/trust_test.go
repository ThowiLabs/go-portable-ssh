package sshtrust

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func hostKey(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()
	secret := ed25519.NewKeyFromSeed(bytesOf(seed))
	key, err := ssh.NewPublicKey(secret.Public())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func bytesOf(seed byte) []byte {
	out := make([]byte, ed25519.SeedSize)
	for i := range out {
		out[i] = seed
	}
	return out
}

func TestPinnedKeyRequiresExactFingerprint(t *testing.T) {
	key := hostKey(t, 1)
	fingerprint := ssh.FingerprintSHA256(key)
	if !ValidFingerprint(fingerprint) {
		t.Fatalf("fingerprint rejected: %s", fingerprint)
	}
	callback, err := Pinned(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("node.example:22", nil, key); err != nil {
		t.Fatalf("known key rejected: %v", err)
	}
	var mismatch *HostKeyMismatchError
	if err := callback("node.example:22", nil, hostKey(t, 2)); !errors.As(err, &mismatch) {
		t.Fatalf("changed host key not rejected: %v", err)
	}
	for _, invalid := range []string{"", "SHA256:", "SHA256:unsafe", "MD5:" + fingerprint, fingerprint + "="} {
		if ValidFingerprint(invalid) {
			t.Fatalf("invalid pin accepted: %q", invalid)
		}
		if _, err := Pinned(invalid); err == nil {
			t.Fatalf("invalid pin usable: %q", invalid)
		}
	}
}

func TestDiscoverNeverAuthenticatesUnknownHost(t *testing.T) {
	key := hostKey(t, 3)
	var unknown *UnknownHostKeyError
	err := Discover()("node.example:2222", nil, key)
	if !errors.As(err, &unknown) || unknown.Host != "node.example:2222" || unknown.Algorithm != ssh.KeyAlgoED25519 || unknown.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("discovery did not report the offered key: %v", err)
	}
}
