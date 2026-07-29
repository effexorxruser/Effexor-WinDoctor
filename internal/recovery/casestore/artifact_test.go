package casestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestArtifactStoredByContentHash(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte(`{"hello":"artifact"}`)
	snap, provider := snapshotWithArtifact(t, payload)
	info := mustCommit(t, st, snap, provider, CommitReasonCaseSnapshot)
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	blob := st.blobAbsPath(snap.Case.CaseID, sha)
	got, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("blob mismatch")
	}
	loaded, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EvidenceBundles[0].Artifacts[0].SHA256 != sha {
		t.Fatal("artifact ref lost")
	}
	_ = info
}

func TestArtifactSHAMismatchRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte("good-bytes")
	snap, _ := snapshotWithArtifact(t, payload)
	bad := MapArtifactProvider{Blobs: map[string][]byte{
		snap.EvidenceBundles[0].Artifacts[0].ArtifactID: []byte("bad-bytes!"), // same length as "good-bytes"
	}}
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap, ArtifactProvider: bad, Reason: CommitReasonCaseSnapshot,
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestArtifactSizeMismatchRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte("abc")
	snap, provider := snapshotWithArtifact(t, payload)
	snap.EvidenceBundles[0].Artifacts[0].SizeBytes = 99
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap, ArtifactProvider: provider, Reason: CommitReasonCaseSnapshot,
	})
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestExistingValidBlobReused(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte("reuse-me")
	snap, provider := snapshotWithArtifact(t, payload)
	mustCommit(t, st, snap, provider, CommitReasonCaseSnapshot)

	tracker := &TrackingArtifactProvider{Inner: provider}
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T15:00:00Z")
	mustCommit(t, st, snap2, tracker, CommitReasonCaseSnapshot)
	if len(tracker.Opened) != 0 {
		t.Fatalf("provider should not be consulted for existing blob, opened=%d", len(tracker.Opened))
	}
}

func TestExistingCorruptedBlobRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte("original")
	snap, provider := snapshotWithArtifact(t, payload)
	mustCommit(t, st, snap, provider, CommitReasonCaseSnapshot)
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	blob := st.blobAbsPath(snap.Case.CaseID, sha)
	if err := os.WriteFile(blob, []byte("corrupted-blob-contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T16:00:00Z")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap2, ArtifactProvider: nil, Reason: CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected corrupted blob rejection")
	}
}

func TestMissingArtifactProviderRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap, _ := snapshotWithArtifact(t, []byte("need-provider"))
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap, ArtifactProvider: nil, Reason: CommitReasonCaseSnapshot,
	})
	if err == nil || !strings.Contains(err.Error(), "ArtifactProvider") {
		t.Fatalf("got %v", err)
	}
}

func TestArtifactRelativePathNeverOpened(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte(`{"x":1}`)
	snap, provider := snapshotWithArtifact(t, payload)
	// Place a decoy file at relative_path under temp — Store must not read it.
	decoyDir := filepath.Join(t.TempDir(), "evidence")
	if err := os.MkdirAll(decoyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(decoyDir, "disk-inventory.json")
	if err := os.WriteFile(decoy, []byte("DECOY"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap.EvidenceBundles[0].Artifacts[0].RelativePath = decoy // absolute-looking path still must not be opened
	// Relative path validation may reject absolute; use a relative decoy name only.
	snap.EvidenceBundles[0].Artifacts[0].RelativePath = "evidence/disk-inventory.json"

	tracker := &TrackingArtifactProvider{Inner: provider}
	mustCommit(t, st, snap, tracker, CommitReasonCaseSnapshot)
	if len(tracker.Opened) != 1 {
		t.Fatalf("opened=%d", len(tracker.Opened))
	}
	// Ensure decoy untouched and provider used artifact_id mapping only.
	got, _ := os.ReadFile(decoy)
	if string(got) != "DECOY" {
		t.Fatal("decoy modified")
	}
}

func TestDuplicateArtifactIDDivergentMetadataRejected(t *testing.T) {
	t.Parallel()
	snap := baseSnapshot(t)
	ref1 := domain.ArtifactRef{
		ArtifactID: "artifact-111111111111111111111111", Kind: "json",
		RelativePath: "a.json", SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes: 0, CreatedAt: "2026-07-27T12:01:00Z", MediaClassification: "case_local",
	}
	ref2 := ref1
	ref2.RelativePath = "b.json"
	snap.EvidenceBundles[0].Artifacts = []domain.ArtifactRef{ref1}
	snap.EvidenceBundles = append(snap.EvidenceBundles, snap.EvidenceBundles[0])
	snap.EvidenceBundles[1].EvidenceID = "evidence-cccccccccccccccccccccccc"
	snap.EvidenceBundles[1].Artifacts = []domain.ArtifactRef{ref2}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected divergent artifact metadata rejection")
	}
}

func TestProviderOpenErrorSurfaced(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap, _ := snapshotWithArtifact(t, []byte("x"))
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap, ArtifactProvider: failProvider{}, Reason: CommitReasonCaseSnapshot,
	})
	if err == nil || !errors.Is(err, errors.New("x")) && !strings.Contains(err.Error(), "unexpected EOF") {
		if err == nil {
			t.Fatal("expected error")
		}
	}
}
