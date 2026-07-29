package casestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func publishOrphanSnapshot(t *testing.T, st *Store, snap Snapshot) (snapshotID string) {
	t.Helper()
	defer st.testOnlyClearFailureHooks()
	st.testOnlySetFailureCheckpoint("after_snapshot_published")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected injected failure after snapshot publish")
	}
	st.testOnlyClearFailureHooks()

	entries, err := os.ReadDir(st.snapshotsDir(snap.Case.CaseID))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	if len(ids) != 1 {
		t.Fatalf("want exactly one published orphan snapshot, got %v", ids)
	}
	commits, err := os.ReadDir(st.commitsDir(snap.Case.CaseID))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range commits {
		if !e.IsDir() && !isTempStoreName(e.Name()) {
			t.Fatalf("unexpected commit after orphan publish: %s", e.Name())
		}
	}
	return ids[0]
}

func assertNoCommits(t *testing.T, st *Store, caseID string) {
	t.Helper()
	entries, err := os.ReadDir(st.commitsDir(caseID))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || isTempStoreName(e.Name()) {
			continue
		}
		if filepath.Ext(e.Name()) == ".json" {
			t.Fatalf("unexpected commit file %s", e.Name())
		}
	}
}

func TestOrphanReuseCorruptedDocumentRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	snapID := publishOrphanSnapshot(t, st, snap)

	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, snapID), "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest","tampered":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected IntegrityError on corrupted orphan reuse")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	assertNoCommits(t, st, snap.Case.CaseID)
}

func TestOrphanReuseMissingDocumentRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	snapID := publishOrphanSnapshot(t, st, snap)

	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, snapID), "documents", "targets", "target-disk-nvme0n1.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected IntegrityError on missing orphan document")
	}
	if !errors.As(err, new(*IntegrityError)) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	assertNoCommits(t, st, snap.Case.CaseID)
}

func TestOrphanReuseExtraDocumentRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	snapID := publishOrphanSnapshot(t, st, snap)

	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, snapID), "documents", "extra.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected IntegrityError on extra orphan document")
	}
	if !errors.As(err, new(*IntegrityError)) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	assertNoCommits(t, st, snap.Case.CaseID)
}

func TestOrphanReuseValidSucceeds(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	snapID := publishOrphanSnapshot(t, st, snap)

	info, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err != nil {
		t.Fatalf("valid orphan reuse Commit: %v", err)
	}
	if info.SnapshotID != snapID {
		t.Fatalf("snapshot id=%s want orphan %s", info.SnapshotID, snapID)
	}
	if info.Sequence != 1 {
		t.Fatalf("sequence=%d want 1", info.Sequence)
	}

	stageEntries, err := os.ReadDir(st.stagingDir(snap.Case.CaseID))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(stageEntries) != 0 {
		names := make([]string, 0, len(stageEntries))
		for _, e := range stageEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("staging not cleaned after orphan reuse: %v", names)
	}

	loaded, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID || loaded.Case.CaseID != snap.Case.CaseID {
		t.Fatalf("load after reuse mismatch: %+v", got)
	}
}
