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
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	entropy := options.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	st := &Store{root: abs, clock: clock, entropy: entropy}
	if err := ensureNotSymlink(abs); err != nil {
		return nil, err
	}
	casesDir := filepath.Join(abs, "cases")
	if _, err := st.ensureManagedDir(casesDir, "before_cases_parent_sync"); err != nil {
		return nil, err
	}
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

func (s *Store) ensureCaseDirs(caseID string) ([]string, error) {
	if err := validateCaseID(caseID); err != nil {
		return nil, err
	}
	dirs := []string{
		s.caseDir(caseID),
		s.snapshotsDir(caseID),
		s.commitsDir(caseID),
		s.stagingDir(caseID),
		s.artifactsDir(caseID),
	}
	checkpoints := []string{
		"before_case_directory_parent_sync",
		"before_snapshots_directory_parent_sync",
		"before_commits_directory_parent_sync",
		"before_staging_directory_parent_sync",
		"before_artifacts_directory_parent_sync",
	}
	var warnings []string
	for _, d := range dirs {
		if err := s.ensureManagedPath(d); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	for i, d := range dirs {
		w, err := s.ensureManagedDir(d, checkpoints[i])
		warnings = append(warnings, w...)
		if err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

func (s *Store) ensureManagedDir(path, checkpoint string) ([]string, error) {
	if err := s.ensureUnderRoot(path); err != nil {
		return nil, err
	}
	if err := s.ensureManagedPath(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if err := s.ensureManagedPath(path); err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: managed path %q is not a directory", ErrPathUnsafe, path)
		}
		return nil, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	parent := filepath.Dir(path)
	var warnings []string
	if !samePath(parent, path) && !samePath(parent, filepath.Clean(s.root)) {
		w, err := s.ensureManagedDir(parent, checkpoint)
		warnings = append(warnings, w...)
		if err != nil {
			return warnings, err
		}
	}
	if err := s.ensureManagedPath(parent); err != nil {
		return warnings, err
	}
	if err := os.Mkdir(path, dirPerm); err != nil {
		if !os.IsExist(err) {
			return warnings, err
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return warnings, statErr
		}
		if !info.IsDir() {
			return warnings, fmt.Errorf("%w: managed path %q is not a directory", ErrPathUnsafe, path)
		}
		return warnings, s.ensureManagedPath(path)
	}
	w, err := s.syncDirChecked(parent, checkpoint)
	warnings = append(warnings, w...)
	if err != nil {
		return warnings, err
	}
	return warnings, s.ensureManagedPath(path)
}

func (s *Store) withCaseLock(caseID string, fn func() error) error {
	lockPath := s.lockPath(caseID)
	if err := s.ensureManagedPath(lockPath); err != nil {
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
