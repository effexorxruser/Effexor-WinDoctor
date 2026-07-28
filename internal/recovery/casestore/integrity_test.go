package casestore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptedDocumentDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "documents", "case-manifest.json")
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected corruption error")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %T %v", err, err)
	}
}

func TestMissingDocumentDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "documents", "case-manifest.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected missing document")
	}
}

func TestUnexpectedSnapshotFileDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "documents", "extra.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected unexpected file error")
	}
}

func TestCorruptedManifestDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "snapshot-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"snapshot-manifest","broken":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected manifest corruption")
	}
}

func TestCorruptedFinalCommitDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(info.Sequence, info.CommitID))
	if err := os.WriteFile(path, []byte(`{not-json`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected commit corruption")
	}
}

func TestCommitSequenceGapDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	// Write a second commit with sequence 3 (gap).
	rec := commitRecord{
		SchemaName:             schemaCommitRecord,
		SchemaVersion:          schemaVersion,
		CaseID:                 snap.Case.CaseID,
		Sequence:               3,
		CommitID:               "commit-dddddddddddddddddddddddd",
		ParentCommitID:         &info.CommitID,
		SnapshotID:             info.SnapshotID,
		SnapshotManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CommittedAt:            "2026-07-28T12:00:00Z",
		Reason:                 string(CommitReasonCaseSnapshot),
	}
	raw, _ := json.Marshal(rec)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(3, rec.CommitID))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected sequence gap")
	}
}

func TestParentMismatchDetected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	badParent := "commit-eeeeeeeeeeeeeeeeeeeeeeee"
	rec := commitRecord{
		SchemaName:             schemaCommitRecord,
		SchemaVersion:          schemaVersion,
		CaseID:                 snap.Case.CaseID,
		Sequence:               2,
		CommitID:               "commit-ffffffffffffffffffffffff",
		ParentCommitID:         &badParent,
		SnapshotID:             info.SnapshotID,
		SnapshotManifestSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CommittedAt:            "2026-07-28T12:00:00Z",
		Reason:                 string(CommitReasonCaseSnapshot),
	}
	raw, _ := json.Marshal(rec)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(2, rec.CommitID))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected parent mismatch")
	}
}

func TestLatestCorruptionDoesNotFallback(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T14:00:00Z")
	c2 := mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)

	// Corrupt latest snapshot documents.
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, c2.SnapshotID), "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected error without fallback")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	if ie.LastValidCommitID != c1.CommitID || ie.LastValidSequence != c1.Sequence || ie.LastValidSnapshotID != c1.SnapshotID {
		t.Fatalf("last valid=%s seq=%d snap=%s want c1 %s seq=%d snap=%s (not failing c2 %s)",
			ie.LastValidCommitID, ie.LastValidSequence, ie.LastValidSnapshotID,
			c1.CommitID, c1.Sequence, c1.SnapshotID, c2.CommitID)
	}
}

func TestCorruptFirstCommitLastValidEmpty(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, c1.SnapshotID), "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected integrity error")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	if ie.LastValidCommitID != "" || ie.LastValidSequence != 0 || ie.LastValidSnapshotID != "" {
		t.Fatalf("want empty LastValid*, got commit=%q seq=%d snap=%q", ie.LastValidCommitID, ie.LastValidSequence, ie.LastValidSnapshotID)
	}
}

func TestCorruptSecondCommitLastValidFirst(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T15:00:00Z")
	c2 := mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)

	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, c2.SnapshotID), "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"broken":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected integrity error")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	if ie.LastValidCommitID != c1.CommitID || ie.LastValidSequence != c1.Sequence || ie.LastValidSnapshotID != c1.SnapshotID {
		t.Fatalf("want LastValid=c1, got commit=%s seq=%d snap=%s", ie.LastValidCommitID, ie.LastValidSequence, ie.LastValidSnapshotID)
	}
}

func TestVerifyAndCleanup(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	stage := filepath.Join(st.stagingDir(snap.Case.CaseID), "txn-leftover")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	orphanSnap := filepath.Join(st.snapshotsDir(snap.Case.CaseID), "snapshot-cccccccccccccccccccccccc")
	if err := os.MkdirAll(filepath.Join(orphanSnap, "documents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanSnap, "snapshot-manifest.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(st.commitsDir(snap.Case.CaseID), "x.json"+tempSuffix)
	if err := os.WriteFile(tmp, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := st.Verify(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status == IntegrityOK {
		t.Fatal("expected degraded/corrupt due to staging/orphans")
	}
	if len(report.StagingEntries) == 0 || len(report.OrphanSnapshots) == 0 {
		t.Fatalf("verify report incomplete: %+v", report)
	}

	ins, err := st.InspectRecovery(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ins.StagingTransactions) == 0 || len(ins.PublishedUncommitted) == 0 {
		t.Fatalf("inspection incomplete: %+v", ins)
	}

	clean, err := st.CleanupStaging(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.RemovedStaging) == 0 {
		t.Fatal("expected staging removal")
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("staging still present")
	}
	if _, err := os.Stat(orphanSnap); err != nil {
		t.Fatal("orphan snapshot must be preserved")
	}
	if _, err := os.Stat(st.snapshotDir(snap.Case.CaseID, info.SnapshotID)); err != nil {
		t.Fatal("committed snapshot must be preserved")
	}
	preserved := false
	for _, s := range clean.PreservedSnapshots {
		if s == info.SnapshotID || s == "snapshot-cccccccccccccccccccccccc" {
			preserved = true
		}
	}
	if !preserved {
		t.Fatalf("preserved list: %v", clean.PreservedSnapshots)
	}
}
