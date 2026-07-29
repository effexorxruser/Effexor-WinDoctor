//go:build unix

package casestore

import (
	"fmt"
	"os"
)

func ensureNotReparsePoint(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink not allowed at %s", ErrPathUnsafe, path)
	}
	return nil
}
