package casestore

import (
	"errors"
	"fmt"
)

var (
	// ErrCaseLocked is returned when another process holds the case lock.
	ErrCaseLocked = errors.New("casestore: case is locked")

	// ErrCaseNotFound is returned when a case directory or commit chain is absent.
	ErrCaseNotFound = errors.New("casestore: case not found")

	// ErrIntegrity indicates a corrupt or inconsistent store state.
	ErrIntegrity = errors.New("casestore: integrity error")

	// ErrInvalidArgument indicates a caller-supplied value failed validation.
	ErrInvalidArgument = errors.New("casestore: invalid argument")

	// ErrPathUnsafe indicates a path escape or forbidden symlink.
	ErrPathUnsafe = errors.New("casestore: unsafe path")

	// ErrRevisionConflict indicates ExpectedParentCommitID did not match the current head.
	ErrRevisionConflict = errors.New("casestore: revision conflict")
)

// CommitOutcomeUnknownError means the commit rename may have succeeded but a
// subsequent durability step failed. Retrying Commit with the same Snapshot is
// safe and must be idempotent.
type CommitOutcomeUnknownError struct {
	CaseID     string
	SnapshotID string
	Cause      error
}

func (e *CommitOutcomeUnknownError) Error() string {
	return fmt.Sprintf("casestore: commit outcome unknown for case %s snapshot %s: %v", e.CaseID, e.SnapshotID, e.Cause)
}

func (e *CommitOutcomeUnknownError) Unwrap() error {
	return e.Cause
}

// IntegrityError wraps ErrIntegrity with context about the last known valid commit.
type IntegrityError struct {
	CaseID              string
	Message             string
	LastValidSequence   uint64
	LastValidCommitID   string
	LastValidSnapshotID string
	Cause               error
}

func (e *IntegrityError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "integrity failure"
	}
	if e.LastValidCommitID != "" {
		return fmt.Sprintf("casestore: %s (last valid commit %s seq=%d): %v", msg, e.LastValidCommitID, e.LastValidSequence, e.Cause)
	}
	return fmt.Sprintf("casestore: %s: %v", msg, e.Cause)
}

func (e *IntegrityError) Unwrap() error {
	if e.Cause != nil {
		return e.Cause
	}
	return ErrIntegrity
}

func (e *IntegrityError) Is(target error) bool {
	return target == ErrIntegrity
}
