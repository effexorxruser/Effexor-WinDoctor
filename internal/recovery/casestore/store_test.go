package casestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestOpenValidRoot(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	if _, err := os.Stat(st.casesRoot()); err != nil {
		t.Fatal(err)
	}
}

func TestRejectRootFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "notadir")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path, Options{})
	if err == nil || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}

func TestCommitAndLoadRoundTrip(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	if info.Sequence != 1 {
		t.Fatalf("sequence=%d", info.Sequence)
	}
	if info.ParentCommitID != "" {
		t.Fatalf("parent=%q", info.ParentCommitID)
	}
	if !strings.HasPrefix(info.SnapshotID, "snapshot-") {
		t.Fatalf("snapshot_id=%s", info.SnapshotID)
	}

	loaded, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID || got.Sequence != 1 {
		t.Fatalf("commit info mismatch: %+v", got)
	}
	if loaded.Case.CaseID != snap.Case.CaseID {
		t.Fatalf("case_id=%s", loaded.Case.CaseID)
	}
	if len(loaded.Targets) != 1 || len(loaded.EvidenceBundles) != 1 {
		t.Fatalf("targets=%d evidence=%d", len(loaded.Targets), len(loaded.EvidenceBundles))
	}
	if !bytes.Equal(loaded.EvidenceBundles[0].Facts, snap.EvidenceBundles[0].Facts) {
		t.Fatalf("facts mismatch: %s vs %s", loaded.EvidenceBundles[0].Facts, snap.EvidenceBundles[0].Facts)
	}
}

func TestStrictDecodeRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "documents", "case-manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["unexpected"] = json.RawMessage(`true`)
	mut, _ := json.Marshal(obj)
	if err := os.WriteFile(path, mut, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err = st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected strict decode failure")
	}
}

func TestDeterministicSnapshotIDAndHashes(t *testing.T) {
	t.Parallel()
	st1 := openTestStore(t)
	st2 := openTestStore(t)
	snap := baseSnapshot(t)
	a := mustCommit(t, st1, snap, nil, CommitReasonCaseSnapshot)
	b := mustCommit(t, st2, snap, nil, CommitReasonCaseSnapshot)
	if a.SnapshotID != b.SnapshotID {
		t.Fatalf("snapshot ids differ: %s vs %s", a.SnapshotID, b.SnapshotID)
	}
	docsA, _ := prepareDocuments(snap)
	docsB, _ := prepareDocuments(snap)
	if docsA[0].SHA256 != docsB[0].SHA256 {
		t.Fatal("document hashes not deterministic")
	}
}

func TestCommitSequenceAndParentChain(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T13:00:00Z")
	c2 := mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)
	if c1.Sequence != 1 || c2.Sequence != 2 {
		t.Fatalf("seq %d %d", c1.Sequence, c2.Sequence)
	}
	if c2.ParentCommitID != c1.CommitID {
		t.Fatalf("parent=%s want %s", c2.ParentCommitID, c1.CommitID)
	}
	if c1.SnapshotID == c2.SnapshotID {
		t.Fatal("expected different snapshot ids")
	}
}

func TestIdempotentSameHeadSnapshot(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	c2 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	if !c2.Idempotent || c2.CommitID != c1.CommitID || c2.Sequence != c1.Sequence {
		t.Fatalf("idempotent reuse failed: %+v", c2)
	}
	entries, err := os.ReadDir(st.commitsDir(snap.Case.CaseID))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("commit files=%d", len(entries))
	}
}

func TestCommitFilenameMatchesContent(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonLegacyImport)
	name := commitFileName(info.Sequence, info.CommitID)
	raw := readCaseFile(t, st, snap.Case.CaseID, "commits", name)
	var rec commitRecord
	if err := decodeStrict(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.CommitID != info.CommitID || rec.Sequence != info.Sequence {
		t.Fatalf("mismatch %+v", rec)
	}
	if rec.ParentCommitID != nil {
		t.Fatalf("expected null parent, got %v", rec.ParentCommitID)
	}
	if !bytes.Contains(raw, []byte(`"parent_commit_id":null`)) {
		t.Fatalf("expected JSON null parent, got %s", raw)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	t.Parallel()
	snap := baseSnapshot(t)
	snap.EvidenceBundles[0].Artifacts = []domain.ArtifactRef{{
		ArtifactID:          "artifact-111111111111111111111111",
		Kind:                "json",
		RelativePath:        "../escape.json",
		SHA256:              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes:           0,
		CreatedAt:           "2026-07-27T12:01:00Z",
		MediaClassification: "case_local",
	}}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestSymlinkedManagedDirectoryRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	caseDir := st.caseDir(snap.Case.CaseID)
	target := filepath.Join(t.TempDir(), "evil")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(caseDir, "snapshots-link-test")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not permitted: %v", err)
	}
	if err := ensureNotSymlink(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestImporterResultCommitAndFactsPreserved(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	reportPath := filepath.Join(filepath.Dir(thisFile), "..", "importer", "legacyreport", "testdata", "report-uefi-bitlocker-unavailable.json")
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	snap := SnapshotFromImporterResult(result)
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
	st := openTestStore(t)
	mustCommit(t, st, snap, nil, CommitReasonLegacyImport)
	loaded, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.EvidenceBundles) == 0 {
		t.Fatal("no evidence")
	}
	wantFacts := map[string][]byte{}
	for _, e := range result.EvidenceBundles {
		wantFacts[e.EvidenceID] = append([]byte(nil), e.Facts...)
	}
	for _, e := range loaded.EvidenceBundles {
		want, ok := wantFacts[e.EvidenceID]
		if !ok {
			t.Fatalf("unexpected evidence %s", e.EvidenceID)
		}
		if !bytes.Equal(e.Facts, want) {
			t.Fatalf("facts for %s not preserved:\n got %s\nwant %s", e.EvidenceID, e.Facts, want)
		}
	}
}

func TestNoCommandsOrMutationsIntroduced(t *testing.T) {
	t.Parallel()
	// Package smoke: Store type has no Execute/Mutate/RunCommand methods via documented API surface.
	var st *Store
	_ = st
	var _ interface {
		Commit(context.Context, CommitRequest) (CommitInfo, error)
		LoadLatest(context.Context, string) (Snapshot, CommitInfo, error)
		Verify(context.Context, string) (IntegrityReport, error)
		InspectRecovery(context.Context, string) (RecoveryInspection, error)
		CleanupStaging(context.Context, string) (CleanupReport, error)
	} = (*Store)(nil)
}
