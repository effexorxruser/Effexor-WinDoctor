package casestore

import (
	"context"
	"errors"
	"testing"
)

func TestParentExpectationAbsentRejectsExisting(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	mustCommit(t, st, snap, nil, CommitReasonLegacyImport)
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot:          mutateCaseUpdatedAt(snap, "2026-07-27T13:00:00Z"),
		Reason:            CommitReasonCaseSnapshot,
		ParentExpectation: ExpectAbsentParent(),
	})
	if !errors.Is(err, ErrCaseExists) {
		t.Fatalf("want ErrCaseExists, got %v", err)
	}
}

func TestParentExpectationCommitConflict(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonLegacyImport)
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot:          mutateCaseUpdatedAt(snap, "2026-07-27T13:00:00Z"),
		Reason:            CommitReasonCaseSnapshot,
		ParentExpectation: ExpectParentCommit("commit-000000000000000000000001"),
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("want ErrRevisionConflict, got %v", err)
	}
	_, err = st.Commit(context.Background(), CommitRequest{
		Snapshot:          mutateCaseUpdatedAt(snap, "2026-07-27T13:00:00Z"),
		Reason:            CommitReasonCaseSnapshot,
		ParentExpectation: ExpectParentCommit(info.CommitID),
	})
	if err != nil {
		t.Fatal(err)
	}
}
