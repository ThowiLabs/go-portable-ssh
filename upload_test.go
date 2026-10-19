package portablessh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runUploadScript(t *testing.T, dest string, overwrite bool, priv Privilege, content []byte) (string, error) {
	t.Helper()
	hash := sha256.Sum256(content)
	script := uploadScript(dest, filepath.Dir(dest), hex.EncodeToString(hash[:]), overwrite, false, 0644, priv)
	command := exec.Command("sh", "-c", script)
	command.Stdin = bytes.NewReader(content)
	returnBytes, err := command.CombinedOutput()
	return string(returnBytes), err
}

func TestUploadScriptPreservesMetadataAndChecksOverwrite(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "file with spaces.txt")
	if err := os.WriteFile(dest, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := runUploadScript(t, dest, false, PrivilegeAuto, []byte("new")); err == nil || !strings.Contains(out, "destination exists") {
		t.Fatalf("expected overwrite protection: %s %v", out, err)
	}
	out, err := runUploadScript(t, dest, true, PrivilegeAuto, []byte("replacement"))
	if err != nil {
		t.Fatalf("upload: %s %v", out, err)
	}
	if !strings.Contains(out, "PORTABLE_SSH_UPLOAD_OK:direct") {
		t.Fatal(out)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("contents: %q %v", data, err)
	}
	stat, err := os.Stat(dest)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", stat, err)
	}
}

func TestUploadScriptRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "keep.txt")
	dest := filepath.Join(dir, "link")
	if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, dest); err != nil {
		t.Fatal(err)
	}
	output, err := runUploadScript(t, dest, true, PrivilegeAuto, []byte("changed"))
	if err == nil || !strings.Contains(output, "symbolic-link destination refused") {
		t.Fatalf("symlink accepted: %s %v", output, err)
	}
	unchanged, _ := os.ReadFile(source)
	if string(unchanged) != "original" {
		t.Fatal("symlink target overwritten")
	}
}

func TestUploadRejectsUnsafeInput(t *testing.T) {
	for _, value := range []string{"", "relative", "/", "/tmp/../root/test", "/tmp/a\nb"} {
		_, err := Upload(context.Background(), nil, UploadOptions{RemotePath: value})
		if err == nil {
			t.Fatalf("invalid input accepted: %q", value)
		}
	}
	if got := shellQuote("path with 'quote'"); got != "'path with '\\''quote'\\'''" {
		t.Fatalf("escaping changed: %q", got)
	}
}
