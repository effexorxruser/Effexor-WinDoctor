package casestore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestValidateManifestDocumentPath(t *testing.T) {
	t.Parallel()
	ok := []string{
		"case-manifest.json",
		"targets/target-disk-nvme0n1.json",
		"evidence/evidence-bbbbbbbbbbbbbbbbbbbbbbbb.json",
	}
	for _, p := range ok {
		if err := validateManifestDocumentPath(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	bad := []string{
		"extra.json",
		"targets/not-a-target.json",
		"evidence/bad-id.json",
		"targets/nested/target-disk-nvme0n1.json",
		"other/case-manifest.json",
	}
	for _, p := range bad {
		if err := validateManifestDocumentPath(p); err == nil {
			t.Fatalf("%s: expected error", p)
		}
	}
}

func TestCompareCanonicalDocumentsMismatch(t *testing.T) {
	t.Parallel()
	snap := baseSnapshot(t)
	docs, err := prepareDocuments(snap)
	if err != nil {
		t.Fatal(err)
	}
	manifestDocs := make([]snapshotDocumentEntry, len(docs))
	for i, d := range docs {
		manifestDocs[i] = snapshotDocumentEntry{
			RelativePath: d.RelativePath,
			SHA256:       d.SHA256,
			SizeBytes:    d.SizeBytes,
			MediaType:    d.MediaType,
		}
	}
	manifest := snapshotManifest{Documents: manifestDocs}
	if err := compareCanonicalDocuments(manifest, snap); err != nil {
		t.Fatalf("matching docs: %v", err)
	}
	manifest.Documents[0].SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	err = compareCanonicalDocuments(manifest, snap)
	if err == nil {
		t.Fatal("expected hash mismatch")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}

func TestCompareCanonicalDocumentsExtraEntry(t *testing.T) {
	t.Parallel()
	snap := baseSnapshot(t)
	docs, err := prepareDocuments(snap)
	if err != nil {
		t.Fatal(err)
	}
	manifestDocs := make([]snapshotDocumentEntry, 0, len(docs)+1)
	for _, d := range docs {
		manifestDocs = append(manifestDocs, snapshotDocumentEntry{
			RelativePath: d.RelativePath,
			SHA256:       d.SHA256,
			SizeBytes:    d.SizeBytes,
			MediaType:    d.MediaType,
		})
	}
	manifestDocs = append(manifestDocs, snapshotDocumentEntry{
		RelativePath: "extra.json",
		SHA256:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SizeBytes:    2,
		MediaType:    mediaTypeJSON,
	})
	if err := compareCanonicalDocuments(snapshotManifest{Documents: manifestDocs}, snap); err == nil {
		t.Fatal("expected count mismatch")
	}
}

func TestNonCanonicalDocumentPathInManifestRejected(t *testing.T) {
	t.Parallel()
	manifest := snapshotManifest{
		SchemaName:    schemaSnapshotManifest,
		SchemaVersion: schemaVersion,
		CaseID:        "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotID:    "snapshot-aaaaaaaaaaaaaaaaaaaaaaaa",
		ContentSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CreatedAt:     "2026-07-27T12:00:00Z",
		Documents: []snapshotDocumentEntry{{
			RelativePath: "extra.json",
			SHA256:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SizeBytes:    2,
			MediaType:    mediaTypeJSON,
		}},
		Artifacts: []snapshotArtifactEntry{},
	}
	err := validateSnapshotManifest(manifest, manifest.CaseID, manifest.CaseID)
	if err == nil {
		t.Fatal("expected non-canonical path rejection")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}

func tamperSnapshotDocument(t *testing.T, st *Store, caseID, snapshotID, rel string, mutate func([]byte) []byte) (newSnapshotID, manifestSHA string) {
	t.Helper()
	docsPath := filepath.Join(st.snapshotDir(caseID, snapshotID), "documents", filepath.FromSlash(rel))
	raw, err := os.ReadFile(docsPath)
	if err != nil {
		t.Fatal(err)
	}
	out := mutate(raw)
	if err := os.WriteFile(docsPath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(st.snapshotDir(caseID, snapshotID), "snapshot-manifest.json")
	mraw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest snapshotManifest
	if err := decodeStrict(mraw, &manifest); err != nil {
		t.Fatal(err)
	}
	sum := sha256Hex(out)
	found := false
	for i := range manifest.Documents {
		if manifest.Documents[i].RelativePath == rel {
			manifest.Documents[i].SHA256 = sum
			manifest.Documents[i].SizeBytes = int64(len(out))
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("document %s missing from manifest", rel)
	}
	contentSHA, newID, err := recomputeSnapshotProvenance(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ContentSHA256 = contentSHA
	manifest.SnapshotID = newID
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := st.snapshotDir(caseID, snapshotID)
	newDir := st.snapshotDir(caseID, newID)
	if oldDir != newDir {
		if err := os.Rename(oldDir, newDir); err != nil {
			t.Fatal(err)
		}
	}
	return newID, sha256Hex(encoded)
}

func TestTargetPathIDMismatchRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	newID, manifestSHA := tamperSnapshotDocument(t, st, snap.Case.CaseID, info.SnapshotID, "targets/target-disk-nvme0n1.json", func(raw []byte) []byte {
		var tgt domain.Target
		if err := json.Unmarshal(raw, &tgt); err != nil {
			t.Fatal(err)
		}
		tgt.TargetID = "target-renamed-disk01"
		out, err := json.Marshal(tgt)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})

	_, err := st.loadSnapshotAtCommit(snap.Case.CaseID, commitRecord{
		CaseID:                 snap.Case.CaseID,
		SnapshotID:             newID,
		SnapshotManifestSHA256: manifestSHA,
	})
	if err == nil {
		t.Fatal("expected target path/id mismatch")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}

func TestEvidencePathIDMismatchRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	newID, manifestSHA := tamperSnapshotDocument(t, st, snap.Case.CaseID, info.SnapshotID, "evidence/evidence-bbbbbbbbbbbbbbbbbbbbbbbb.json", func(raw []byte) []byte {
		var ev domain.EvidenceBundle
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		ev.EvidenceID = "evidence-cccccccccccccccccccccccc"
		out, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})

	_, err := st.loadSnapshotAtCommit(snap.Case.CaseID, commitRecord{
		CaseID:                 snap.Case.CaseID,
		SnapshotID:             newID,
		SnapshotManifestSHA256: manifestSHA,
	})
	if err == nil {
		t.Fatal("expected evidence path/id mismatch")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}

func TestNonCanonicalJSONBytesRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	newID, manifestSHA := tamperSnapshotDocument(t, st, snap.Case.CaseID, info.SnapshotID, "case-manifest.json", func(raw []byte) []byte {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		indented, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if string(indented) == string(raw) {
			t.Fatal("indented form unexpectedly identical")
		}
		return indented
	})

	// Retarget commit so LoadLatest exercises the full path.
	chain, err := st.loadCommitChain(snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	head := chain[len(chain)-1]
	oldPath := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(head.Sequence, head.CommitID))
	head.SnapshotID = newID
	head.SnapshotManifestSHA256 = manifestSHA
	newCommitID, err := computeCommitIDFromRecord(head)
	if err != nil {
		t.Fatal(err)
	}
	head.CommitID = newCommitID
	out, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(head.Sequence, head.CommitID))
	if err := os.WriteFile(newPath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if newPath != oldPath {
		_ = os.Remove(oldPath)
	}

	_, _, err = st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected canonical document mismatch for indented JSON")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}
