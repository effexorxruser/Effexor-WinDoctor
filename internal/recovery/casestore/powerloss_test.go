package casestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFailureInjectionBeforeCommitPoints(t *testing.T) {
	checkpoints := []string{
		"after_staging_created",
		"after_documents_written",
		"after_artifacts_written",
		"after_manifest_written",
		"after_snapshot_published",
		"before_commit_published",
	}
	for _, cp := range checkpoints {
		cp := cp
		t.Run(cp, func(t *testing.T) {
			st := openTestStore(t)
			defer st.testOnlyClearFailureHooks()
			snap := baseSnapshot(t)
			st.testOnlySetFailureCheckpoint(cp)
			_, err := st.Commit(context.Background(), CommitRequest{
				Snapshot: snap,
				Reason:   CommitReasonCaseSnapshot,
			})
			if err == nil {
				t.Fatal("expected injected failure")
			}
			st.testOnlyClearFailureHooks()

			_, _, loadErr := st.LoadLatest(context.Background(), snap.Case.CaseID)
			if loadErr == nil {
				t.Fatal("LoadLatest must not see uncommitted snapshot")
			}
			if !errors.Is(loadErr, ErrCaseNotFound) {
				// May be not found; ensure it isn't silently succeeding.
				t.Logf("load err: %v", loadErr)
			}

			info, err := st.Commit(context.Background(), CommitRequest{
				Snapshot: snap,
				Reason:   CommitReasonCaseSnapshot,
			})
			if err != nil {
				t.Fatalf("retry commit: %v", err)
			}
			if info.Sequence != 1 || info.Idempotent {
				// First successful commit after failure.
				if info.Sequence != 1 {
					t.Fatalf("sequence=%d", info.Sequence)
				}
			}
			loaded, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Case.CaseID != snap.Case.CaseID {
				t.Fatal("round trip failed")
			}
		})
	}
}

func TestFailureAfterCommitPublishedIsVisibleAndIdempotent(t *testing.T) {
	st := openTestStore(t)
	defer st.testOnlyClearFailureHooks()
	snap := baseSnapshot(t)
	st.testOnlySetFailureCheckpoint("after_commit_published")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	var unknown *CommitOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("want CommitOutcomeUnknownError, got %v", err)
	}
	st.testOnlyClearFailureHooks()

	loaded, info, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatalf("commit should be visible: %v", err)
	}
	if loaded.Case.CaseID != snap.Case.CaseID {
		t.Fatal("bad load")
	}
	retry := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	if !retry.Idempotent || retry.CommitID != info.CommitID {
		t.Fatalf("retry not idempotent: %+v", retry)
	}
	entries, _ := os.ReadDir(st.commitsDir(snap.Case.CaseID))
	if len(entries) != 1 {
		t.Fatalf("duplicate commits: %d", len(entries))
	}
}

func TestFailureAfterDirectorySyncUnknownOutcome(t *testing.T) {
	st := openTestStore(t)
	defer st.testOnlyClearFailureHooks()
	snap := baseSnapshot(t)
	st.testOnlySetFailureCheckpoint("after_commit_directory_sync")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	var unknown *CommitOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("want unknown outcome, got %v", err)
	}
	st.testOnlyClearFailureHooks()
	retry := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	if !retry.Idempotent {
		t.Fatalf("expected idempotent retry, got %+v", retry)
	}
}

func TestStagingIgnoredByLoadLatest(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	stage := filepath.Join(st.stagingDir(snap.Case.CaseID), "txn-orphan")
	if err := os.MkdirAll(filepath.Join(stage, "documents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "snapshot-manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID || loaded.Case.CaseID != snap.Case.CaseID {
		t.Fatal("staging affected load")
	}
}

func TestOrphanSnapshotIgnored(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	orphan := filepath.Join(st.snapshotsDir(snap.Case.CaseID), "snapshot-ffffffffffffffffffffffff")
	if err := os.MkdirAll(filepath.Join(orphan, "documents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "snapshot-manifest.json"), []byte(`{"schema_name":"snapshot-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SnapshotID != info.SnapshotID {
		t.Fatalf("got %s", got.SnapshotID)
	}
}

func TestTempCommitIgnored(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	tmp := filepath.Join(st.commitsDir(snap.Case.CaseID), "00000000000000000099-commit-cccccccccccccccccccccccc.json"+tempSuffix)
	if err := os.WriteFile(tmp, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID {
		t.Fatal("temp commit affected head")
	}
}
