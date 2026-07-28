package casestore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const filePerm = 0o644
const dirPerm = 0o755

// writeFileDurable writes data atomically: temp in same dir (O_EXCL), sync,
// close, rename, then best-effort parent directory sync.
func writeFileDurable(path string, data []byte, entropy io.Reader) (warnings []string, err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	if err := ensureNotSymlink(dir); err != nil {
		return nil, err
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	var tmp string
	var f *os.File
	for i := 0; i < 8; i++ {
		suffix, err := randomHex(entropy, 8)
		if err != nil {
			return nil, err
		}
		tmp = filepath.Join(dir, filepath.Base(path)+"."+suffix+tempSuffix)
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return nil, err
		}
		f = nil
	}
	if f == nil {
		return nil, fmt.Errorf("casestore: unable to create exclusive temp file for %s", path)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	written := 0
	for written < len(data) {
		n, werr := f.Write(data[written:])
		written += n
		if werr != nil {
			return nil, werr
		}
	}
	if written != len(data) {
		return nil, fmt.Errorf("casestore: short write to %s: %d/%d", tmp, written, len(data))
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	cleanup = false

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	warnings, err = syncDir(dir)
	return warnings, err
}

func randomHex(r io.Reader, nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func syncDir(dir string) ([]string, error) {
	return syncDirPlatform(dir)
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		// Fall back to read-only open for sync attempt.
		f, err = os.Open(path)
		if err != nil {
			return err
		}
	}
	defer f.Close()
	return f.Sync()
}

func renameDurable(oldpath, newpath string) ([]string, error) {
	if err := os.Rename(oldpath, newpath); err != nil {
		return nil, err
	}
	warnings, err := syncDir(filepath.Dir(newpath))
	return warnings, err
}

func durabilityWarning(msg string) string {
	return msg + " (platform=" + runtime.GOOS + ")"
}
