package casestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	if err := ensureDirNotSymlink(s.caseDir(caseID)); err != nil {
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
	if err := validateSnapshotManifest(manifest); err != nil {
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

func validateSnapshotManifest(m snapshotManifest) error {
	if m.SchemaName != schemaSnapshotManifest || m.SchemaVersion != schemaVersion {
		return fmt.Errorf("%w: invalid snapshot manifest schema", ErrIntegrity)
	}
	if err := validateCaseID(m.CaseID); err != nil {
		return err
	}
	if err := validateSnapshotID(m.SnapshotID); err != nil {
		return err
	}
	if err := validateSHA256Hex(m.ContentSHA256); err != nil {
		return err
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
		if err := validateCommitRecord(rec); err != nil {
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

func validateCommitRecord(r commitRecord) error {
	if r.SchemaName != schemaCommitRecord || r.SchemaVersion != schemaVersion {
		return fmt.Errorf("invalid commit schema")
	}
	if err := validateCaseID(r.CaseID); err != nil {
		return err
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
	if r.Reason != string(CommitReasonLegacyImport) && r.Reason != string(CommitReasonCaseSnapshot) {
		return fmt.Errorf("invalid reason %q", r.Reason)
	}
	return nil
}
