package casestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupStagingOnlyRemovesReservedEntries(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap, provider := snapshotWithArtifact(t, []byte(`{"ok":true}`))
	_ = mustCommit(t, st, snap, provider, CommitReasonCaseSnapshot)

	stageRoot := st.stagingDir(snap.Case.CaseID)
	removeTxn := filepath.Join(stageRoot, "txn-remove-me")
	keepDir := filepath.Join(stageRoot, "keep-dir")
	keepFile := filepath.Join(stageRoot, "notes.txt")
	if err := os.MkdirAll(removeTxn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keepFile, []byte("preserve"), 0o644); err != nil {
		t.Fatal(err)
	}

	commitTemp := filepath.Join(st.commitsDir(snap.Case.CaseID), "reserved"+tempSuffix)
	commitGenericTmp := filepath.Join(st.commitsDir(snap.Case.CaseID), "generic.tmp")
	if err := os.WriteFile(commitTemp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commitGenericTmp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	artifactTmpDir := filepath.Join(st.artifactsDir(snap.Case.CaseID), "ff")
	if err := os.MkdirAll(artifactTmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artifactTemp := filepath.Join(artifactTmpDir, "blob"+tempSuffix)
	artifactGenericTmp := filepath.Join(artifactTmpDir, "blob.tmp")
	if err := os.WriteFile(artifactTemp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactGenericTmp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := st.CleanupStaging(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(removeTxn); !os.IsNotExist(err) {
		t.Fatalf("txn dir still present: %v", err)
	}
	if _, err := os.Stat(keepDir); err != nil {
		t.Fatalf("keep dir removed: %v", err)
	}
	if _, err := os.Stat(keepFile); err != nil {
		t.Fatalf("keep file removed: %v", err)
	}
	if _, err := os.Stat(commitTemp); !os.IsNotExist(err) {
		t.Fatalf("reserved commit temp still present: %v", err)
	}
	if _, err := os.Stat(commitGenericTmp); err != nil {
		t.Fatalf("generic .tmp should be preserved: %v", err)
	}
	if _, err := os.Stat(artifactTemp); !os.IsNotExist(err) {
		t.Fatalf("reserved artifact temp still present: %v", err)
	}
	if _, err := os.Stat(artifactGenericTmp); err != nil {
		t.Fatalf("artifact generic .tmp should be preserved: %v", err)
	}
	if len(report.RemovedStaging) != 1 || report.RemovedStaging[0] != "txn-remove-me" {
		t.Fatalf("RemovedStaging=%v", report.RemovedStaging)
	}
	if len(report.RemovedTemporary) != 2 {
		t.Fatalf("RemovedTemporary=%v", report.RemovedTemporary)
	}
}
