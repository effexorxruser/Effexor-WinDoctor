package casestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectRecoveryKeepsValidPrefixOnBrokenTail(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T14:00:00Z")
	c2 := mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)
	snap3 := mutateCaseUpdatedAt(snap, "2026-07-27T16:00:00Z")
	c3 := mustCommit(t, st, snap3, nil, CommitReasonCaseSnapshot)

	// Corrupt the third commit file so the chain prefix is c1+c2.
	badPath := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(c3.Sequence, c3.CommitID))
	if err := os.WriteFile(badPath, []byte(`{not-json`), 0o644); err != nil {
		t.Fatal(err)
	}

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
	for _, p := range ins.PublishedUncommitted {
		if p == c1.SnapshotID || p == c2.SnapshotID {
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
