//go:build windows

package casestore

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

func syncDirPlatform(dir string) ([]string, error) {
	// Windows does not expose a portable directory fsync equivalent that is
	// reliable across all filesystems. Report best-effort durability.
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("casestore: not a directory: %s", dir)
	}
	return []string{durabilityWarning("directory fsync is best-effort on Windows; metadata durability is not guaranteed on all volumes")}, nil
}

type windowsCaseLock struct {
	handle windows.Handle
	path   string
}

func (l *windowsCaseLock) Unlock() error {
	if l.handle == 0 || l.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(l.handle)
	l.handle = 0
	return err
}

func acquireCaseLock(path string) (caseLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // share mode 0: exclusive
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if isSharingViolation(err) {
			return nil, ErrCaseLocked
		}
		return nil, fmt.Errorf("casestore: acquire lock: %w", err)
	}
	return &windowsCaseLock{handle: handle, path: path}, nil
}

func isSharingViolation(err error) bool {
	for err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == windows.ERROR_SHARING_VIOLATION || errno == windows.ERROR_LOCK_VIOLATION {
				return true
			}
		}
		if errno, ok := err.(windows.Errno); ok {
			if errno == windows.ERROR_SHARING_VIOLATION || errno == windows.ERROR_LOCK_VIOLATION {
				return true
			}
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}
