package casestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// LoadLatest loads the highest valid committed snapshot for caseID.
// Incomplete staging, temp files, and orphan snapshots are ignored.
// A corrupt latest commit does not silently fall back to an older commit.
func (s *Store) LoadLatest(ctx context.Context, caseID string) (Snapshot, CommitInfo, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, CommitInfo{}, err
	}
	if err := validateCaseID(caseID); err != nil {
		return Snapshot{}, CommitInfo{}, err
	}
	if err := s.ensureCaseTreeSafe(caseID); err != nil {
		return Snapshot{}, CommitInfo{}, err
	}

	chain, err := s.loadCommitChain(caseID)
	if err != nil {
		return Snapshot{}, CommitInfo{}, err
	}
	if len(chain) == 0 {
		return Snapshot{}, CommitInfo{}, fmt.Errorf("%w: %s", ErrCaseNotFound, caseID)
	}

	head := chain[len(chain)-1]
	snap, err := s.loadSnapshotAtCommit(caseID, head)
	if err != nil {
		return Snapshot{}, CommitInfo{}, &IntegrityError{
			CaseID:              caseID,
			Message:             "latest committed state is corrupt; refusing automatic fallback",
			LastValidSequence:   head.Sequence,
			LastValidCommitID:   head.CommitID,
			LastValidSnapshotID: head.SnapshotID,
			Cause:               err,
		}
	}
	info := CommitInfo{
		CaseID:         caseID,
		SnapshotID:     head.SnapshotID,
		CommitID:       head.CommitID,
		Sequence:       head.Sequence,
		ParentCommitID: parentString(head.ParentCommitID),
		CommittedAt:    head.CommittedAt,
		Idempotent:     false,
	}
	return snap, info, nil
}

func (s *Store) loadSnapshotAtCommit(caseID string, head commitRecord) (Snapshot, error) {
	if err := validateSnapshotID(head.SnapshotID); err != nil {
		return Snapshot{}, err
	}
	snapDir := s.snapshotDir(caseID, head.SnapshotID)
	if err := ensureDirNotSymlink(snapDir); err != nil {
		return Snapshot{}, err
	}
	manifestPath := filepath.Join(snapDir, "snapshot-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Snapshot{}, err
	}
	if sha256Hex(raw) != head.SnapshotManifestSHA256 {
		return Snapshot{}, fmt.Errorf("%w: snapshot manifest hash mismatch", ErrIntegrity)
	}
	var manifest snapshotManifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot manifest: %w", err)
	}
	if err := validateSnapshotManifest(manifest, caseID, head.CaseID); err != nil {
		return Snapshot{}, err
	}
	if manifest.SnapshotID != head.SnapshotID {
		return Snapshot{}, fmt.Errorf("%w: manifest snapshot_id mismatch", ErrIntegrity)
	}

	docsDir := filepath.Join(snapDir, "documents")
	if err := ensureDirNotSymlink(docsDir); err != nil {
		return Snapshot{}, err
	}
	expected := make(map[string]snapshotDocumentEntry, len(manifest.Documents))
	for _, d := range manifest.Documents {
		expected[d.RelativePath] = d
	}
	found := map[string]struct{}{}
	err = filepath.Walk(docsDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return ensureNotSymlink(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink document %s", ErrPathUnsafe, path)
		}
		rel, err := filepath.Rel(docsDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		entry, ok := expected[relSlash]
		if !ok {
			return fmt.Errorf("%w: unexpected document file %s", ErrIntegrity, relSlash)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(raw)) != entry.SizeBytes {
			return fmt.Errorf("%w: document %s size mismatch", ErrIntegrity, relSlash)
		}
		if sha256Hex(raw) != entry.SHA256 {
			return fmt.Errorf("%w: document %s hash mismatch", ErrIntegrity, relSlash)
		}
		found[relSlash] = struct{}{}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	for rel := range expected {
		if _, ok := found[rel]; !ok {
			return Snapshot{}, fmt.Errorf("%w: missing document %s", ErrIntegrity, rel)
		}
	}

	var snap Snapshot
	caseRaw, err := os.ReadFile(filepath.Join(docsDir, "case-manifest.json"))
	if err != nil {
		return Snapshot{}, err
	}
	if err := domain.DecodeAndValidateJSON(caseRaw, &snap.Case); err != nil {
		return Snapshot{}, fmt.Errorf("case-manifest: %w", err)
	}

	for _, d := range manifest.Documents {
		switch {
		case strings.HasPrefix(d.RelativePath, "targets/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var t domain.Target
			if err := domain.DecodeAndValidateJSON(raw, &t); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			snap.Targets = append(snap.Targets, t)
		case strings.HasPrefix(d.RelativePath, "evidence/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var e domain.EvidenceBundle
			if err := domain.DecodeAndValidateJSON(raw, &e); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			snap.EvidenceBundles = append(snap.EvidenceBundles, e)
		}
	}
	sort.Slice(snap.Targets, func(i, j int) bool { return snap.Targets[i].TargetID < snap.Targets[j].TargetID })
	sort.Slice(snap.EvidenceBundles, func(i, j int) bool {
		return snap.EvidenceBundles[i].EvidenceID < snap.EvidenceBundles[j].EvidenceID
	})
	if err := snap.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := compareManifestArtifacts(manifest, snap); err != nil {
		return Snapshot{}, err
	}

	for _, a := range manifest.Artifacts {
		blob := s.blobAbsPath(caseID, a.SHA256)
		if err := ensureNotSymlink(blob); err != nil {
			return Snapshot{}, err
		}
		ok, err := verifyBlobFile(blob, a.SHA256, a.SizeBytes)
		if err != nil {
			return Snapshot{}, fmt.Errorf("artifact %s: %w", a.ArtifactID, err)
		}
		if !ok {
			return Snapshot{}, fmt.Errorf("%w: artifact blob %s hash/size mismatch", ErrIntegrity, a.SHA256)
		}
	}
	return snap, nil
}

func validateSnapshotManifest(m snapshotManifest, caseID, commitCaseID string) error {
	if m.SchemaName != schemaSnapshotManifest || m.SchemaVersion != schemaVersion {
		return fmt.Errorf("%w: invalid snapshot manifest schema", ErrIntegrity)
	}
	if m.Documents == nil {
		return fmt.Errorf("%w: snapshot manifest documents must be an array", ErrIntegrity)
	}
	if m.Artifacts == nil {
		return fmt.Errorf("%w: snapshot manifest artifacts must be an array", ErrIntegrity)
	}
	if err := validateCaseID(m.CaseID); err != nil {
		return err
	}
	if m.CaseID != caseID {
		return fmt.Errorf("%w: manifest case_id %q does not match requested %q", ErrIntegrity, m.CaseID, caseID)
	}
	if m.CaseID != commitCaseID {
		return fmt.Errorf("%w: manifest case_id %q does not match commit case_id %q", ErrIntegrity, m.CaseID, commitCaseID)
	}
	if err := validateSnapshotID(m.SnapshotID); err != nil {
		return err
	}
	if err := validateSHA256Hex(m.ContentSHA256); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("%w: invalid created_at %q", ErrIntegrity, m.CreatedAt)
	}

	seenDocs := make(map[string]struct{}, len(m.Documents))
	for i, d := range m.Documents {
		if err := rejectTraversal(d.RelativePath); err != nil {
			return fmt.Errorf("%w: documents[%d].relative_path: %v", ErrIntegrity, i, err)
		}
		if _, ok := seenDocs[d.RelativePath]; ok {
			return fmt.Errorf("%w: duplicate document relative_path %q", ErrIntegrity, d.RelativePath)
		}
		seenDocs[d.RelativePath] = struct{}{}
		if err := validateSHA256Hex(d.SHA256); err != nil {
			return fmt.Errorf("%w: documents[%d]: %v", ErrIntegrity, i, err)
		}
		if d.SizeBytes < 0 {
			return fmt.Errorf("%w: documents[%d] negative size", ErrIntegrity, i)
		}
		if d.MediaType != mediaTypeJSON {
			return fmt.Errorf("%w: documents[%d] media_type must be %q", ErrIntegrity, i, mediaTypeJSON)
		}
	}

	seenArts := make(map[string]struct{}, len(m.Artifacts))
	for i, a := range m.Artifacts {
		if err := validateArtifactID(a.ArtifactID); err != nil {
			return fmt.Errorf("%w: artifacts[%d]: %v", ErrIntegrity, i, err)
		}
		if _, ok := seenArts[a.ArtifactID]; ok {
			return fmt.Errorf("%w: duplicate artifact_id %q", ErrIntegrity, a.ArtifactID)
		}
		seenArts[a.ArtifactID] = struct{}{}
		if err := validateSHA256Hex(a.SHA256); err != nil {
			return fmt.Errorf("%w: artifacts[%d]: %v", ErrIntegrity, i, err)
		}
		if a.SizeBytes < 0 {
			return fmt.Errorf("%w: artifacts[%d] negative size", ErrIntegrity, i)
		}
		if err := rejectTraversal(a.BlobRelativePath); err != nil {
			return fmt.Errorf("%w: artifacts[%d].blob_relative_path: %v", ErrIntegrity, i, err)
		}
		wantBlob := blobRelativePath(a.SHA256)
		if a.BlobRelativePath != wantBlob {
			return fmt.Errorf("%w: artifacts[%d] blob_relative_path want %q got %q", ErrIntegrity, i, wantBlob, a.BlobRelativePath)
		}
		if a.Kind == "" {
			return fmt.Errorf("%w: artifacts[%d] kind required", ErrIntegrity, i)
		}
		if a.MediaClassification == "" {
			return fmt.Errorf("%w: artifacts[%d] media_classification required", ErrIntegrity, i)
		}
	}

	contentSHA, snapshotID, err := recomputeSnapshotProvenance(m)
	if err != nil {
		return err
	}
	if contentSHA != m.ContentSHA256 {
		return fmt.Errorf("%w: content_sha256 mismatch", ErrIntegrity)
	}
	if snapshotID != m.SnapshotID {
		return fmt.Errorf("%w: snapshot_id mismatch with recomputed provenance", ErrIntegrity)
	}
	return nil
}

func recomputeSnapshotProvenance(m snapshotManifest) (contentSHA, snapshotID string, err error) {
	docEntries := append([]snapshotDocumentEntry(nil), m.Documents...)
	if docEntries == nil {
		docEntries = []snapshotDocumentEntry{}
	}
	sort.Slice(docEntries, func(i, j int) bool { return docEntries[i].RelativePath < docEntries[j].RelativePath })
	artsCopy := append([]snapshotArtifactEntry(nil), m.Artifacts...)
	if artsCopy == nil {
		artsCopy = []snapshotArtifactEntry{}
	}
	sort.Slice(artsCopy, func(i, j int) bool { return artsCopy[i].ArtifactID < artsCopy[j].ArtifactID })

	body := struct {
		SchemaName    string                  `json:"schema_name"`
		SchemaVersion string                  `json:"schema_version"`
		CaseID        string                  `json:"case_id"`
		CreatedAt     string                  `json:"created_at"`
		Documents     []snapshotDocumentEntry `json:"documents"`
		Artifacts     []snapshotArtifactEntry `json:"artifacts"`
	}{
		SchemaName:    schemaSnapshotManifest,
		SchemaVersion: schemaVersion,
		CaseID:        m.CaseID,
		CreatedAt:     m.CreatedAt,
		Documents:     docEntries,
		Artifacts:     artsCopy,
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(canonical)
	contentSHA = hex.EncodeToString(sum[:])
	snapshotID = "snapshot-" + contentSHA[:24]
	return contentSHA, snapshotID, nil
}

func compareManifestArtifacts(manifest snapshotManifest, snap Snapshot) error {
	refs, err := collectArtifactRefs(snap)
	if err != nil {
		return err
	}
	if len(refs) != len(manifest.Artifacts) {
		return fmt.Errorf("%w: manifest artifacts count %d != snapshot refs %d", ErrIntegrity, len(manifest.Artifacts), len(refs))
	}
	byID := make(map[string]domain.ArtifactRef, len(refs))
	for _, r := range refs {
		byID[r.ArtifactID] = r
	}
	for _, a := range manifest.Artifacts {
		ref, ok := byID[a.ArtifactID]
		if !ok {
			return fmt.Errorf("%w: manifest artifact %s missing from snapshot", ErrIntegrity, a.ArtifactID)
		}
		sha := strings.ToLower(ref.SHA256)
		if a.SHA256 != sha || a.SizeBytes != ref.SizeBytes || a.Kind != ref.Kind || a.MediaClassification != ref.MediaClassification {
			return fmt.Errorf("%w: manifest artifact %s diverges from snapshot refs", ErrIntegrity, a.ArtifactID)
		}
		if a.BlobRelativePath != blobRelativePath(sha) {
			return fmt.Errorf("%w: manifest artifact %s blob path mismatch", ErrIntegrity, a.ArtifactID)
		}
		delete(byID, a.ArtifactID)
	}
	if len(byID) != 0 {
		for id := range byID {
			return fmt.Errorf("%w: snapshot artifact %s missing from manifest", ErrIntegrity, id)
		}
	}
	return nil
}

type loadedCommit struct {
	record commitRecord
	path   string
}

func (s *Store) loadCommitChain(caseID string) ([]commitRecord, error) {
	dir := s.commitsDir(caseID)
	if err := ensureDirNotSymlink(dir); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var loaded []loadedCommit
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || isTempStoreName(name) || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := ensureNotSymlink(path); err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, &IntegrityError{CaseID: caseID, Message: "failed reading commit", Cause: err}
		}
		var rec commitRecord
		if err := decodeStrict(raw, &rec); err != nil {
			return nil, &IntegrityError{
				CaseID:  caseID,
				Message: "malformed final commit record " + name,
				Cause:   err,
			}
		}
		if err := validateCommitRecord(rec, caseID); err != nil {
			return nil, &IntegrityError{CaseID: caseID, Message: "invalid commit " + name, Cause: err}
		}
		wantName := commitFileName(rec.Sequence, rec.CommitID)
		if name != wantName {
			return nil, &IntegrityError{
				CaseID:  caseID,
				Message: fmt.Sprintf("commit filename %s does not match content (%s)", name, wantName),
				Cause:   ErrIntegrity,
			}
		}
		loaded = append(loaded, loadedCommit{record: rec, path: path})
	}

	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].record.Sequence < loaded[j].record.Sequence
	})

	out := make([]commitRecord, 0, len(loaded))
	for i, item := range loaded {
		rec := item.record
		wantSeq := uint64(i + 1)
		if rec.Sequence != wantSeq {
			return nil, &IntegrityError{
				CaseID:            caseID,
				Message:           fmt.Sprintf("commit sequence gap: got %d want %d", rec.Sequence, wantSeq),
				LastValidSequence: uint64(i),
				Cause:             ErrIntegrity,
			}
		}
		if i == 0 {
			if rec.ParentCommitID != nil {
				return nil, &IntegrityError{
					CaseID:  caseID,
					Message: "first commit must have null parent_commit_id",
					Cause:   ErrIntegrity,
				}
			}
		} else {
			prev := out[i-1]
			if rec.ParentCommitID == nil || *rec.ParentCommitID != prev.CommitID {
				return nil, &IntegrityError{
					CaseID:              caseID,
					Message:             "parent_commit_id mismatch",
					LastValidSequence:   prev.Sequence,
					LastValidCommitID:   prev.CommitID,
					LastValidSnapshotID: prev.SnapshotID,
					Cause:               ErrIntegrity,
				}
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

func validateCommitRecord(r commitRecord, caseID string) error {
	if r.SchemaName != schemaCommitRecord || r.SchemaVersion != schemaVersion {
		return fmt.Errorf("invalid commit schema")
	}
	if err := validateCaseID(r.CaseID); err != nil {
		return err
	}
	if r.CaseID != caseID {
		return fmt.Errorf("%w: commit case_id %q does not match requested %q", ErrIntegrity, r.CaseID, caseID)
	}
	if r.Sequence < 1 {
		return fmt.Errorf("sequence must be >= 1")
	}
	if err := validateCommitID(r.CommitID); err != nil {
		return err
	}
	if r.ParentCommitID != nil {
		if err := validateCommitID(*r.ParentCommitID); err != nil {
			return err
		}
	}
	if err := validateSnapshotID(r.SnapshotID); err != nil {
		return err
	}
	if err := validateSHA256Hex(r.SnapshotManifestSHA256); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, r.CommittedAt); err != nil {
		return fmt.Errorf("%w: invalid committed_at %q", ErrIntegrity, r.CommittedAt)
	}
	if r.Reason != string(CommitReasonLegacyImport) && r.Reason != string(CommitReasonCaseSnapshot) {
		return fmt.Errorf("invalid reason %q", r.Reason)
	}
	wantID, err := computeCommitIDFromRecord(r)
	if err != nil {
		return err
	}
	if wantID != r.CommitID {
		return fmt.Errorf("%w: commit_id mismatch with recomputed provenance", ErrIntegrity)
	}
	return nil
}
