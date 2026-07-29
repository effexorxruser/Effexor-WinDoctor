package casestore

import (
	"context"
	"errors"
	"testing"
)

func TestInjectedDirectorySyncFailureBlocksCommitBeforeMarker(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	defer st.testOnlyClearFailureHooks()
	snap := baseSnapshot(t)
	st.testOnlySetFailureCheckpoint("before_documents_directory_sync")

	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected injected sync failure")
	}
	var injected *injectedFailureError
	if !errors.As(err, &injected) {
		t.Fatalf("want injectedFailureError, got %v", err)
	}
	assertNoCommits(t, st, snap.Case.CaseID)
	_, _, loadErr := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if !errors.Is(loadErr, ErrCaseNotFound) {
		t.Fatalf("LoadLatest err=%v want ErrCaseNotFound", loadErr)
	}
}
