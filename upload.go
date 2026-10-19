package portablessh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Privilege string

const (
	PrivilegeAuto  Privilege = "auto"
	PrivilegeNever Privilege = "never"
	PrivilegeSudo  Privilege = "sudo"
)

type UploadOptions struct {
	LocalPath     string
	RemotePath    string
	Overwrite     bool
	CreateParents bool
	Mode          os.FileMode
	Privilege     Privilege // Empty uses auto; sudo requires non-interactive authorization on the host.
}

type UploadResult struct {
	RemotePath string
	Bytes      int64
	SHA256     string
	Elevated   bool
}

// Upload preserves UID, GID and mode on overwrite. New files use Mode (0644 by default).
// GNU/Linux hosts need sh, install, mktemp, stat, sha256sum and (when required) sudo -n.
func (c *Client) Upload(ctx context.Context, opts UploadOptions) (UploadResult, error) {
	return Upload(ctx, c.conn, opts)
}

// Upload uses an existing verified SSH connection; it does not open another login.
func Upload(ctx context.Context, conn *ssh.Client, opts UploadOptions) (UploadResult, error) {
	if conn == nil {
		return UploadResult{}, errors.New("SSH connection is required")
	}
	if err := ctx.Err(); err != nil {
		return UploadResult{}, err
	}
	dest := strings.TrimSpace(opts.RemotePath)
	if !strings.HasPrefix(dest, "/") || dest == "/" || path.Clean(dest) != dest || strings.ContainsRune(dest, 0) || strings.Contains(dest, "\n") {
		return UploadResult{}, errors.New("remote_path must be a clean absolute file path")
	}
	priv := opts.Privilege
	if priv == "" {
		priv = PrivilegeAuto
	}
	if priv != PrivilegeAuto && priv != PrivilegeNever && priv != PrivilegeSudo {
		return UploadResult{}, errors.New("invalid upload privilege mode")
	}
	if opts.Mode&^os.FileMode(0777) != 0 {
		return UploadResult{}, errors.New("mode must contain only file permission bits")
	}
	mode := opts.Mode.Perm()
	if mode == 0 {
		mode = 0644
	}
	source, err := os.Open(opts.LocalPath)
	if err != nil {
		return UploadResult{}, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return UploadResult{}, err
	}
	if !info.Mode().IsRegular() {
		return UploadResult{}, errors.New("local_path is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, source); err != nil {
		return UploadResult{}, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return UploadResult{}, err
	}
	script := uploadScript(dest, path.Dir(dest), digest, opts.Overwrite, opts.CreateParents, mode, priv)
	session, err := conn.NewSession()
	if err != nil {
		return UploadResult{}, err
	}
	defer session.Close()
	var stdout, stderr outputBuffer
	session.Stdin = source
	session.Stdout = &stdout
	session.Stderr = &stderr
	finished := make(chan error, 1)
	go func() { finished <- session.Run("sh -c " + shellQuote(script)) }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return UploadResult{}, ctx.Err()
	case err := <-finished:
		out, _ := stdout.snapshot()
		errs, _ := stderr.snapshot()
		if err != nil {
			return UploadResult{}, fmt.Errorf("SSH upload: %w: %s", err, strings.TrimSpace(errs))
		}
		status := strings.TrimSpace(out)
		if status != "PORTABLE_SSH_UPLOAD_OK:direct" && status != "PORTABLE_SSH_UPLOAD_OK:sudo" {
			return UploadResult{}, fmt.Errorf("unexpected SSH upload response: %q", status)
		}
		return UploadResult{RemotePath: dest, Bytes: info.Size(), SHA256: digest, Elevated: status == "PORTABLE_SSH_UPLOAD_OK:sudo"}, nil
	}
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func uploadScript(remote, parent, digest string, overwrite, createParents bool, mode os.FileMode, priv Privilege) string {
	var b strings.Builder
	b.WriteString("set -eu\numask 077\n")
	fmt.Fprintf(&b, "dest=%s\nparent=%s\n", shellQuote(remote), shellQuote(parent))
	fmt.Fprintf(&b, "permission=%s\npolicy=%s\n", shellQuote(fmt.Sprintf("%04o", mode)), shellQuote(string(priv)))
	fmt.Fprintf(&b, "expected=%s\n", shellQuote(digest))
	if createParents {
		b.WriteString("if ! mkdir -p -- \"$parent\" 2>/dev/null; then\n")
		b.WriteString("  if [ \"$policy\" = never ]; then exit 13; fi\n  sudo -n mkdir -p -- \"$parent\"\nfi\n")
	}
	b.WriteString(`[ -d "$parent" ] || { [ "$policy" != never ] && sudo -n test -d "$parent"; } || { echo 'destination parent missing' >&2; exit 2; }
`)
	b.WriteString(`needs_sudo=0
if [ "$policy" = sudo ] || [ ! -w "$parent" ]; then needs_sudo=1; fi
if [ "$needs_sudo" = 1 ]; then
  [ "$policy" != never ] || { echo 'permission denied; elevation disabled' >&2; exit 13; }
  sudo -n true
  if sudo -n test -L "$dest"; then echo 'symbolic-link destination refused' >&2; exit 2; fi
  if sudo -n test -e "$dest"; then
    sudo -n test -f "$dest" || { echo 'not a regular-file destination' >&2; exit 2; }
`)
	if !overwrite {
		b.WriteString("    echo 'destination exists' >&2; exit 73\n")
	}
	b.WriteString(`    :
  fi
else
  [ ! -L "$dest" ] || { echo 'symbolic-link destination refused' >&2; exit 2; }
  [ ! -e "$dest" ] || [ -f "$dest" ] || { echo 'not a regular-file destination' >&2; exit 2; }
`)
	if !overwrite {
		b.WriteString("  [ ! -e \"$dest\" ] || { echo 'destination exists' >&2; exit 73; }\n")
	}
	b.WriteString("fi\n")
	b.WriteString("source=$(mktemp /tmp/.portable-ssh-source.XXXXXXXX)\n")
	b.WriteString("target=''\nelevated=direct\n")
	b.WriteString("cleanup(){ rm -f -- \"$source\"; if [ -n \"$target\" ]; then sudo -n rm -f -- \"$target\" 2>/dev/null || rm -f -- \"$target\" 2>/dev/null || :; fi; }\n")
	b.WriteString("trap cleanup EXIT HUP INT TERM\ncat > \"$source\"\n")
	b.WriteString("actual=$(sha256sum \"$source\"); actual=${actual%% *}\n[ \"$actual\" = \"$expected\" ] || { echo 'SHA256 mismatch' >&2; exit 65; }\n")
	b.WriteString(`owner=$(id -u)
group=$(id -g)
if [ "$needs_sudo" = 1 ]; then
  if sudo -n test -e "$dest"; then
    owner=$(sudo -n stat -c %u -- "$dest")
    group=$(sudo -n stat -c %g -- "$dest")
    permission=$(sudo -n stat -c %a -- "$dest")
  else
    owner=$(sudo -n stat -c %u -- "$parent")
    group=$(sudo -n stat -c %g -- "$parent")
  fi
else
  if [ -e "$dest" ]; then
    owner=$(stat -c %u -- "$dest")
    group=$(stat -c %g -- "$dest")
    permission=$(stat -c %a -- "$dest")
  fi
  if [ "$owner" != "$(id -u)" ]; then needs_sudo=1; fi
  case " $(id -G) " in *" $group "*) ;; *) needs_sudo=1;; esac
fi
if [ "$needs_sudo" = 1 ]; then
  [ "$policy" != never ] || { echo 'permission denied; elevation disabled' >&2; exit 13; }
  sudo -n true
fi
`)
	// A same-directory target makes replacement atomic and leaves existing data intact on errors.
	b.WriteString("if [ \"$needs_sudo\" = 0 ]; then\n")
	b.WriteString("  target=$(mktemp \"$parent/.portable-ssh-upload.XXXXXXXX\")\n")
	b.WriteString("  install -m \"$permission\" -- \"$source\" \"$target\"\n")
	b.WriteString("  chgrp \"$group\" -- \"$target\"\n")
	b.WriteString("else\n  elevated=sudo\n")
	b.WriteString("  target=$(sudo -n mktemp \"$parent/.portable-ssh-upload.XXXXXXXX\")\n")
	b.WriteString("  sudo -n install -o \"$owner\" -g \"$group\" -m \"$permission\" -- \"$source\" \"$target\"\nfi\n")
	b.WriteString(`if [ "$elevated" = sudo ]; then
  if sudo -n test -L "$dest"; then echo 'destination changed into symlink' >&2; exit 2; fi
else
  [ ! -L "$dest" ] || { echo 'destination changed into symlink' >&2; exit 2; }
fi
`)
	if !overwrite {
		b.WriteString("[ ! -e \"$dest\" ] || { echo 'destination appeared before commit' >&2; exit 73; }\n")
	}
	if overwrite {
		b.WriteString("if [ \"$elevated\" = sudo ]; then sudo -n mv -f -- \"$target\" \"$dest\"; else mv -f -- \"$target\" \"$dest\"; fi\n")
	} else {
		b.WriteString("if [ \"$elevated\" = sudo ]; then sudo -n ln -- \"$target\" \"$dest\"; else ln -- \"$target\" \"$dest\"; fi\n")
		b.WriteString("if [ \"$elevated\" = sudo ]; then sudo -n rm -f -- \"$target\"; else rm -f -- \"$target\"; fi\n")
	}
	b.WriteString("target=''\nprintf 'PORTABLE_SSH_UPLOAD_OK:%s\\n' \"$elevated\"\n")
	return b.String()
}
