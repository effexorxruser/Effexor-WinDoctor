//go:build unix

package casestore

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func syncDirPlatform(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return nil, nil
}

type unixCaseLock struct {
	file *os.File
}

func (l *unixCaseLock) Unlock() error {
	if l.file == nil {
		return nil
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	cerr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return cerr
}

func acquireCaseLock(path string) (caseLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, ErrCaseLocked
		}
		return nil, fmt.Errorf("casestore: flock: %w", err)
	}
	return &unixCaseLock{file: f}, nil
}
