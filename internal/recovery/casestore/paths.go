package casestore

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reCaseID             = regexp.MustCompile(`^case-[a-f0-9]{24}$`)
	reSnapshotID         = regexp.MustCompile(`^snapshot-[a-f0-9]{24}$`)
	reCommitID           = regexp.MustCompile(`^commit-[a-f0-9]{24}$`)
	reSHA256             = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reTargetID           = regexp.MustCompile(`^target-[a-z0-9-]{8,64}$`)
	reEvidenceID         = regexp.MustCompile(`^evidence-[a-f0-9]{24}$`)
	reFindingID          = regexp.MustCompile(`^finding-[a-f0-9]{24}$`)
	rePlanID             = regexp.MustCompile(`^plan-[a-f0-9]{24}$`)
	reExecutionID        = regexp.MustCompile(`^exec-[a-f0-9]{24}$`)
	reVerificationID     = regexp.MustCompile(`^verify-[a-f0-9]{24}$`)
	reArtifactID         = regexp.MustCompile(`^artifact-[a-f0-9]{24}$`)
	reCoordinatorEventID = regexp.MustCompile(`^cevt-[a-f0-9]{24}$`)
	reAcquisitionID      = regexp.MustCompile(`^acq-[a-f0-9]{24}$`)
)

func (s *Store) casesRoot() string {
	return filepath.Join(s.root, "cases")
}

func (s *Store) caseDir(caseID string) string {
	return filepath.Join(s.casesRoot(), caseID)
}

func (s *Store) snapshotsDir(caseID string) string {
	return filepath.Join(s.caseDir(caseID), "snapshots")
}

func (s *Store) snapshotDir(caseID, snapshotID string) string {
	return filepath.Join(s.snapshotsDir(caseID), snapshotID)
}

func (s *Store) commitsDir(caseID string) string {
	return filepath.Join(s.caseDir(caseID), "commits")
}

func (s *Store) stagingDir(caseID string) string {
	return filepath.Join(s.caseDir(caseID), "staging")
}

func (s *Store) artifactsDir(caseID string) string {
	return filepath.Join(s.caseDir(caseID), "artifacts", "sha256")
}

func (s *Store) lockPath(caseID string) string {
	return filepath.Join(s.caseDir(caseID), "case.lock")
}

func blobRelativePath(sha256Hex string) string {
	return "artifacts/sha256/" + sha256Hex[:2] + "/" + sha256Hex
}

func (s *Store) blobAbsPath(caseID, sha256Hex string) string {
	return filepath.Join(s.caseDir(caseID), filepath.FromSlash(blobRelativePath(sha256Hex)))
}

func commitFileName(sequence uint64, commitID string) string {
	return fmt.Sprintf("%020d-%s.json", sequence, commitID)
}

func validateCaseID(caseID string) error {
	if !reCaseID.MatchString(caseID) {
		return fmt.Errorf("%w: invalid case_id %q", ErrInvalidArgument, caseID)
	}
	return nil
}

func validateSnapshotID(id string) error {
	if !reSnapshotID.MatchString(id) {
		return fmt.Errorf("%w: invalid snapshot_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateCommitID(id string) error {
	if !reCommitID.MatchString(id) {
		return fmt.Errorf("%w: invalid commit_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateTargetID(id string) error {
	if !reTargetID.MatchString(id) {
		return fmt.Errorf("%w: invalid target_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateEvidenceID(id string) error {
	if !reEvidenceID.MatchString(id) {
		return fmt.Errorf("%w: invalid evidence_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateFindingID(id string) error {
	if !reFindingID.MatchString(id) {
		return fmt.Errorf("%w: invalid finding_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validatePlanID(id string) error {
	if !rePlanID.MatchString(id) {
		return fmt.Errorf("%w: invalid plan_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateExecutionID(id string) error {
	if !reExecutionID.MatchString(id) {
		return fmt.Errorf("%w: invalid execution_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateVerificationID(id string) error {
	if !reVerificationID.MatchString(id) {
		return fmt.Errorf("%w: invalid verification_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateCoordinatorEventID(id string) error {
	if !reCoordinatorEventID.MatchString(id) {
		return fmt.Errorf("%w: invalid coordinator event_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateAcquisitionID(id string) error {
	if !reAcquisitionID.MatchString(id) {
		return fmt.Errorf("%w: invalid acquisition_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateArtifactID(id string) error {
	if !reArtifactID.MatchString(id) {
		return fmt.Errorf("%w: invalid artifact_id %q", ErrInvalidArgument, id)
	}
	return nil
}

func validateSHA256Hex(value string) error {
	if !reSHA256.MatchString(value) {
		return fmt.Errorf("%w: invalid sha256 %q", ErrInvalidArgument, value)
	}
	return nil
}

func rejectTraversal(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrPathUnsafe)
	}
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) {
		return fmt.Errorf("%w: absolute path %q", ErrPathUnsafe, path)
	}
	if len(path) >= 2 && path[1] == ':' {
		return fmt.Errorf("%w: absolute path %q", ErrPathUnsafe, path)
	}
	clean := filepath.ToSlash(path)
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return fmt.Errorf("%w: path traversal in %q", ErrPathUnsafe, path)
		}
	}
	if strings.Contains(clean, "../") || strings.Contains(path, `..\`) {
		return fmt.Errorf("%w: path traversal in %q", ErrPathUnsafe, path)
	}
	return nil
}

func (s *Store) ensureUnderRoot(abs string) error {
	cleanRoot, err := filepath.Abs(s.root)
	if err != nil {
		return err
	}
	cleanAbs, err := filepath.Abs(abs)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(cleanRoot, cleanAbs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathUnsafe, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%w: path %q escapes store root", ErrPathUnsafe, abs)
	}
	return nil
}

// ensureManagedPath checks that path is under the store root and that every
// ancestor from path up to and including root is not a symlink/reparse point.
func (s *Store) ensureManagedPath(path string) error {
	if err := s.ensureUnderRoot(path); err != nil {
		return err
	}
	cleanRoot, err := filepath.Abs(s.root)
	if err != nil {
		return err
	}
	cleanAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cur := cleanAbs
	for {
		if err := ensureNotSymlink(cur); err != nil {
			return err
		}
		if samePath(cur, cleanRoot) {
			break
		}
		parent := filepath.Dir(cur)
		if samePath(parent, cur) {
			return fmt.Errorf("%w: path %q escaped while walking ancestors", ErrPathUnsafe, path)
		}
		cur = parent
		// Defensive: refuse walking above root even if Rel was confused.
		rel, err := filepath.Rel(cleanRoot, cur)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			if !samePath(cur, cleanRoot) {
				return fmt.Errorf("%w: ancestor walk escaped store root for %q", ErrPathUnsafe, path)
			}
		}
	}
	return nil
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// ensureNotSymlink rejects symlinks and (on Windows) any reparse point.
func ensureNotSymlink(path string) error {
	return ensureNotReparsePoint(path)
}

func ensureDirNotSymlink(path string) error {
	return ensureNotSymlink(path)
}

func isStagingTxnName(name string) bool {
	return strings.HasPrefix(name, "txn-")
}

func isTempStoreName(name string) bool {
	return strings.HasSuffix(name, tempSuffix)
}
