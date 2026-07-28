package casestore

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Store is a local crash-consistent case store rooted at an explicit directory.
type Store struct {
	root    string
	clock   Clock
	entropy io.Reader
	// test-only; nil/empty in production
	failureCheckpoint string
	failureHook       func(string) error
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// Open opens a Case Store at root. Root must already exist as a directory.
// Open creates the cases/ subdirectory if needed.
func Open(root string, options Options) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: root is required", ErrInvalidArgument)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("%w: root %q: %v", ErrInvalidArgument, root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: root %q is not a directory", ErrInvalidArgument, root)
	}
	if err := ensureNotSymlink(abs); err != nil {
		return nil, err
	}
	casesDir := filepath.Join(abs, "cases")
	if err := os.MkdirAll(casesDir, dirPerm); err != nil {
		return nil, err
	}
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	entropy := options.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	st := &Store{root: abs, clock: clock, entropy: entropy}
	if err := st.ensureCasesRootSafe(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) ensureCasesRootSafe() error {
	return s.ensureManagedPath(s.casesRoot())
}

// ensureCaseTreeSafe verifies key managed directories for a case are under the
// store root with no symlink/reparse ancestors.
func (s *Store) ensureCaseTreeSafe(caseID string) error {
	if err := validateCaseID(caseID); err != nil {
		return err
	}
	paths := []string{
		s.caseDir(caseID),
		s.snapshotsDir(caseID),
		s.commitsDir(caseID),
		s.stagingDir(caseID),
		s.artifactsDir(caseID),
	}
	for _, p := range paths {
		if err := s.ensureManagedPath(p); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureCaseDirs(caseID string) error {
	if err := validateCaseID(caseID); err != nil {
		return err
	}
	dirs := []string{
		s.caseDir(caseID),
		s.snapshotsDir(caseID),
		s.commitsDir(caseID),
		s.stagingDir(caseID),
		s.artifactsDir(caseID),
	}
	for _, d := range dirs {
		if err := ensureNotSymlink(d); err != nil {
			return err
		}
		if err := os.MkdirAll(d, dirPerm); err != nil {
			return err
		}
		if err := ensureNotSymlink(d); err != nil {
			return err
		}
		if err := s.ensureUnderRoot(d); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) withCaseLock(caseID string, fn func() error) error {
	if err := s.ensureCaseDirs(caseID); err != nil {
		return err
	}
	lockPath := s.lockPath(caseID)
	if err := s.ensureUnderRoot(lockPath); err != nil {
		return err
	}
	lk, err := acquireCaseLock(lockPath)
	if err != nil {
		return err
	}
	defer func() { _ = lk.Unlock() }()
	return fn()
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
