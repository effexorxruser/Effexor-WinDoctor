//go:build windows

package casestore

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
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

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_FILE_NOT_FOUND {
			return nil
		}
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: reparse point not allowed at %s", ErrPathUnsafe, path)
	}
	return nil
}
