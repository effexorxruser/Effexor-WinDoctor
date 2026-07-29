package casestore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// rerouteCommitParent rewrites a commit record so its parent_commit_id points
// to newParentID. It recomputes commit_id and renames the file to match,
// producing a record that passes validateCommitRecord and filename checks but
// breaks the chain link.  Returns the new file path.
func rerouteCommitParent(t *testing.T, st *Store, caseID string, seq uint64, oldCommitID, newParentID string) string {
	t.Helper()
	dir := st.commitsDir(caseID)
	oldName := commitFileName(seq, oldCommitID)
	oldPath := filepath.Join(dir, oldName)

	raw, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec commitRecord
	if err := decodeStrict(raw, &rec); err != nil {
		t.Fatal(err)
	}

	rec.ParentCommitID = &newParentID

	newID, err := computeCommitIDFromRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.CommitID = newID

	out, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}

	newName := commitFileName(rec.Sequence, rec.CommitID)
	newPath := filepath.Join(dir, newName)
	if err := os.WriteFile(newPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if newName != oldName {
		if err := os.Remove(oldPath); err != nil {
			t.Fatal(err)
		}
	}
	return newPath
}

func TestInspectRecoveryKeepsValidPrefixOnBrokenTail(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T14:00:00Z")
	c2 := mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)
	snap3 := mutateCaseUpdatedAt(snap, "2026-07-27T16:00:00Z")
	c3 := mustCommit(t, st, snap3, nil, CommitReasonCaseSnapshot)

	// Reroute c3's parent from c2 to c1: record stays parseable and passes
	// filename/content validation but breaks the chain link.
	badPath := rerouteCommitParent(t, st, snap.Case.CaseID, c3.Sequence, c3.CommitID, c1.CommitID)

	ins, err := st.InspectRecovery(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if !ins.BrokenCommitChain {
		t.Fatal("expected BrokenCommitChain")
	}
	if len(ins.BrokenCommitTail) == 0 {
		t.Fatal("expected BrokenCommitTail entries")
	}
	foundBad := false
	for _, name := range ins.BrokenCommitTail {
		if name == filepath.Base(badPath) {
			foundBad = true
		}
	}
	if !foundBad {
		t.Fatalf("BrokenCommitTail=%v want %s", ins.BrokenCommitTail, filepath.Base(badPath))
	}

	wantSnaps := map[string]bool{c1.SnapshotID: true, c2.SnapshotID: true}
	if len(ins.ValidCommittedSnapshots) != 2 {
		t.Fatalf("ValidCommittedSnapshots=%v", ins.ValidCommittedSnapshots)
	}
	for _, id := range ins.ValidCommittedSnapshots {
		if !wantSnaps[id] {
			t.Fatalf("unexpected valid snapshot %s", id)
		}
	}
	wantCommits := map[string]bool{c1.CommitID: true, c2.CommitID: true}
	if len(ins.ValidCommitIDs) != 2 {
		t.Fatalf("ValidCommitIDs=%v", ins.ValidCommitIDs)
	}
	for _, id := range ins.ValidCommitIDs {
		if !wantCommits[id] {
			t.Fatalf("unexpected valid commit %s", id)
		}
	}
	wantReferenced := map[string]bool{c1.SnapshotID: true, c2.SnapshotID: true, c3.SnapshotID: true}
	if len(ins.ReferencedFinalSnapshots) != 3 {
		t.Fatalf("ReferencedFinalSnapshots=%v", ins.ReferencedFinalSnapshots)
	}
	for _, id := range ins.ReferencedFinalSnapshots {
		if !wantReferenced[id] {
			t.Fatalf("unexpected referenced final snapshot %s", id)
		}
	}
	if len(ins.BrokenTailSnapshots) != 1 || ins.BrokenTailSnapshots[0] != c3.SnapshotID {
		t.Fatalf("BrokenTailSnapshots=%v want [%s]", ins.BrokenTailSnapshots, c3.SnapshotID)
	}
	for _, p := range ins.PublishedUncommitted {
		if p == c1.SnapshotID || p == c2.SnapshotID || p == c3.SnapshotID {
			t.Fatalf("valid-prefix snapshot %s must not be PublishedUncommitted", p)
		}
	}

	report, err := st.Verify(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if report.CommitCount != 2 {
		t.Fatalf("CommitCount=%d want 2", report.CommitCount)
	}
	if report.Status != IntegrityCorrupt {
		t.Fatalf("Status=%s want corrupt", report.Status)
	}
	if report.LatestCommit != c2.CommitID {
		t.Fatalf("LatestCommit=%s want %s", report.LatestCommit, c2.CommitID)
	}
}
