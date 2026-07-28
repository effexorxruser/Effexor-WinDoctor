package casestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// Commit validates and atomically publishes a snapshot for a case.
func (s *Store) Commit(ctx context.Context, request CommitRequest) (CommitInfo, error) {
	if err := ctx.Err(); err != nil {
		return CommitInfo{}, err
	}
	if err := request.Snapshot.Validate(); err != nil {
		return CommitInfo{}, err
	}
	reason := request.Reason
	if reason != CommitReasonLegacyImport && reason != CommitReasonCaseSnapshot {
		return CommitInfo{}, fmt.Errorf("%w: invalid commit reason %q", ErrInvalidArgument, reason)
	}

	caseID := request.Snapshot.Case.CaseID
	if err := s.ensureCaseTreeSafe(caseID); err != nil {
		return CommitInfo{}, err
	}
	var info CommitInfo
	err := s.withCaseLock(caseID, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var cerr error
		info, cerr = s.commitLocked(ctx, request)
		return cerr
	})
	return info, err
}

func (s *Store) commitLocked(ctx context.Context, request CommitRequest) (CommitInfo, error) {
	caseID := request.Snapshot.Case.CaseID
	var warnings []string

	artifacts, err := collectArtifactRefs(request.Snapshot)
	if err != nil {
		return CommitInfo{}, err
	}
	for _, a := range artifacts {
		if err := rejectTraversal(a.RelativePath); err != nil {
			return CommitInfo{}, err
		}
	}

	chain, err := s.loadCommitChain(caseID)
	if err != nil {
		return CommitInfo{}, err
	}
	if err := s.verifyCommittedHistory(caseID, chain); err != nil {
		return CommitInfo{}, err
	}

	docs, err := prepareDocuments(request.Snapshot)
	if err != nil {
		return CommitInfo{}, err
	}

	createdAt := request.Snapshot.Case.UpdatedAt
	// Placeholder artifact entries use blob paths; bytes ingested below.
	artEntries := make([]snapshotArtifactEntry, 0, len(artifacts))
	for _, a := range artifacts {
		sha := strings.ToLower(a.SHA256)
		artEntries = append(artEntries, snapshotArtifactEntry{
			ArtifactID:          a.ArtifactID,
			SHA256:              sha,
			SizeBytes:           a.SizeBytes,
			BlobRelativePath:    blobRelativePath(sha),
			Kind:                a.Kind,
			MediaClassification: a.MediaClassification,
		})
	}

	manifest, manifestBytes, err := buildSnapshotManifest(caseID, createdAt, docs, artEntries)
	if err != nil {
		return CommitInfo{}, err
	}

	if len(chain) > 0 {
		head := chain[len(chain)-1]
		if head.SnapshotID == manifest.SnapshotID {
			return CommitInfo{
				CaseID:             caseID,
				SnapshotID:         head.SnapshotID,
				CommitID:           head.CommitID,
				Sequence:           head.Sequence,
				ParentCommitID:     parentString(head.ParentCommitID),
				CommittedAt:        head.CommittedAt,
				Idempotent:         true,
				DurabilityWarnings: warnings,
			}, nil
		}
	}

	stagingName, err := randomHex(s.entropy, 12)
	if err != nil {
		return CommitInfo{}, err
	}
	stagingRoot := filepath.Join(s.stagingDir(caseID), "txn-"+stagingName)
	if err := s.ensureUnderRoot(stagingRoot); err != nil {
		return CommitInfo{}, err
	}
	if err := os.MkdirAll(stagingRoot, dirPerm); err != nil {
		return CommitInfo{}, err
	}
	if err := s.maybeFail("after_staging_created"); err != nil {
		return CommitInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommitInfo{}, err
	}

	docsDir := filepath.Join(stagingRoot, "documents")
	if err := os.MkdirAll(docsDir, dirPerm); err != nil {
		return CommitInfo{}, err
	}
	for _, d := range docs {
		if err := rejectTraversal(d.RelativePath); err != nil {
			return CommitInfo{}, err
		}
		dest := filepath.Join(docsDir, filepath.FromSlash(d.RelativePath))
		if err := s.ensureUnderRoot(dest); err != nil {
			return CommitInfo{}, err
		}
		if err := os.MkdirAll(filepath.Dir(dest), dirPerm); err != nil {
			return CommitInfo{}, err
		}
		w, err := writeFileDurable(dest, d.Bytes, s.entropy)
		warnings = append(warnings, w...)
		if err != nil {
			return CommitInfo{}, err
		}
	}
	if err := s.maybeFail("after_documents_written"); err != nil {
		return CommitInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommitInfo{}, err
	}

	for _, a := range artifacts {
		if err := s.ingestArtifact(ctx, caseID, a, request.ArtifactProvider, &warnings); err != nil {
			return CommitInfo{}, err
		}
	}
	if err := s.maybeFail("after_artifacts_written"); err != nil {
		return CommitInfo{}, err
	}

	manifestPath := filepath.Join(stagingRoot, "snapshot-manifest.json")
	w, err := writeFileDurable(manifestPath, manifestBytes, s.entropy)
	warnings = append(warnings, w...)
	if err != nil {
		return CommitInfo{}, err
	}
	if err := s.maybeFail("after_manifest_written"); err != nil {
		return CommitInfo{}, err
	}

	finalSnapDir := s.snapshotDir(caseID, manifest.SnapshotID)
	if err := validateSnapshotID(manifest.SnapshotID); err != nil {
		return CommitInfo{}, err
	}
	if err := s.ensureUnderRoot(finalSnapDir); err != nil {
		return CommitInfo{}, err
	}
	if _, err := os.Lstat(finalSnapDir); err == nil {
		// Snapshot already published (orphan from prior crash). Reuse it after verifying manifest hash.
		if err := ensureNotSymlink(finalSnapDir); err != nil {
			return CommitInfo{}, err
		}
		existing, err := os.ReadFile(filepath.Join(finalSnapDir, "snapshot-manifest.json"))
		if err != nil {
			return CommitInfo{}, err
		}
		if sha256Hex(existing) != sha256Hex(manifestBytes) {
			return CommitInfo{}, fmt.Errorf("%w: published snapshot %s has divergent manifest", ErrIntegrity, manifest.SnapshotID)
		}
		_ = os.RemoveAll(stagingRoot)
	} else if os.IsNotExist(err) {
		rw, rerr := renameDurable(stagingRoot, finalSnapDir)
		warnings = append(warnings, rw...)
		if rerr != nil {
			return CommitInfo{}, rerr
		}
	} else {
		return CommitInfo{}, err
	}
	if err := s.maybeFail("after_snapshot_published"); err != nil {
		return CommitInfo{}, err
	}
	if err := s.maybeFail("before_commit_published"); err != nil {
		return CommitInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommitInfo{}, err
	}

	var parent *string
	seq := uint64(1)
	if len(chain) > 0 {
		head := chain[len(chain)-1]
		seq = head.Sequence + 1
		pid := head.CommitID
		parent = &pid
	}

	manifestSHA := sha256Hex(manifestBytes)
	record, recordBytes, err := buildCommitRecord(caseID, seq, parent, manifest.SnapshotID, manifestSHA, formatTime(s.clock.Now()), string(request.Reason))
	if err != nil {
		return CommitInfo{}, err
	}

	commitsDir := s.commitsDir(caseID)
	finalName := commitFileName(record.Sequence, record.CommitID)
	finalPath := filepath.Join(commitsDir, finalName)
	if err := s.ensureUnderRoot(finalPath); err != nil {
		return CommitInfo{}, err
	}
	if _, err := os.Lstat(finalPath); err == nil {
		return CommitInfo{}, fmt.Errorf("%w: commit file already exists: %s", ErrIntegrity, finalName)
	}

	// Publish commit: exclusive temp write + rename, then directory sync with
	// an explicit checkpoint between rename and dir sync.
	if err := writeFileExclusiveRename(finalPath, recordBytes, s.entropy); err != nil {
		return CommitInfo{}, err
	}
	if err := s.maybeFail("after_commit_published"); err != nil {
		return CommitInfo{}, &CommitOutcomeUnknownError{
			CaseID:     caseID,
			SnapshotID: manifest.SnapshotID,
			Cause:      err,
		}
	}

	dw, derr := syncDir(commitsDir)
	warnings = append(warnings, dw...)
	if err := s.maybeFail("after_commit_directory_sync"); err != nil {
		return CommitInfo{}, &CommitOutcomeUnknownError{
			CaseID:     caseID,
			SnapshotID: manifest.SnapshotID,
			Cause:      err,
		}
	}
	if derr != nil {
		return CommitInfo{}, &CommitOutcomeUnknownError{
			CaseID:     caseID,
			SnapshotID: manifest.SnapshotID,
			Cause:      derr,
		}
	}

	return CommitInfo{
		CaseID:             caseID,
		SnapshotID:         manifest.SnapshotID,
		CommitID:           record.CommitID,
		Sequence:           record.Sequence,
		ParentCommitID:     parentString(record.ParentCommitID),
		CommittedAt:        record.CommittedAt,
		Idempotent:         false,
		DurabilityWarnings: warnings,
	}, nil
}

// verifyCommittedHistory fully loads every committed snapshot. Corruption blocks
// both idempotent retries and new appends.
func (s *Store) verifyCommittedHistory(caseID string, chain []commitRecord) error {
	for _, c := range chain {
		if _, err := s.loadSnapshotAtCommit(caseID, c); err != nil {
			return &IntegrityError{
				CaseID:              caseID,
				Message:             "committed history is corrupt; refusing commit",
				LastValidSequence:   c.Sequence,
				LastValidCommitID:   c.CommitID,
				LastValidSnapshotID: c.SnapshotID,
				Cause:               err,
			}
		}
	}
	return nil
}

func (s *Store) ingestArtifact(ctx context.Context, caseID string, ref domain.ArtifactRef, provider ArtifactProvider, warnings *[]string) error {
	sha := strings.ToLower(ref.SHA256)
	if err := validateSHA256Hex(sha); err != nil {
		return err
	}
	dest := s.blobAbsPath(caseID, sha)
	if err := s.ensureUnderRoot(dest); err != nil {
		return err
	}
	if err := ensureNotSymlink(filepath.Dir(dest)); err != nil {
		return err
	}

	if info, err := os.Lstat(dest); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: artifact blob is a symlink", ErrPathUnsafe)
		}
		ok, verr := verifyBlobFile(dest, sha, ref.SizeBytes)
		if verr != nil {
			return verr
		}
		if ok {
			return nil
		}
		return fmt.Errorf("%w: existing blob %s failed hash/size verification", ErrIntegrity, sha)
	} else if !os.IsNotExist(err) {
		return err
	}

	if provider == nil {
		return fmt.Errorf("%w: ArtifactProvider required for artifact %s", ErrInvalidArgument, ref.ArtifactID)
	}
	rc, err := provider.OpenArtifact(ctx, ref)
	if err != nil {
		return fmt.Errorf("open artifact %s: %w", ref.ArtifactID, err)
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(dest), dirPerm); err != nil {
		return err
	}
	tmpSuffix, err := randomHex(s.entropy, 8)
	if err != nil {
		return err
	}
	tmp := dest + "." + tmpSuffix + tempSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, h), rc)
	if err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if written != ref.SizeBytes {
		return fmt.Errorf("%w: artifact %s size mismatch: got %d want %d", ErrInvalidArgument, ref.ArtifactID, written, ref.SizeBytes)
	}
	if got != sha {
		return fmt.Errorf("%w: artifact %s sha256 mismatch: got %s want %s", ErrInvalidArgument, ref.ArtifactID, got, sha)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	cleanup = false
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	w, err := syncDir(filepath.Dir(dest))
	*warnings = append(*warnings, w...)
	return err
}

func verifyBlobFile(path, wantSHA string, wantSize int64) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() != wantSize {
		return false, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	return got == wantSHA, nil
}

func buildCommitRecord(caseID string, seq uint64, parent *string, snapshotID, manifestSHA, committedAt, reason string) (commitRecord, []byte, error) {
	commitID, err := computeCommitID(caseID, seq, parent, snapshotID, manifestSHA, committedAt, reason)
	if err != nil {
		return commitRecord{}, nil, err
	}
	rec := commitRecord{
		SchemaName:             schemaCommitRecord,
		SchemaVersion:          schemaVersion,
		CaseID:                 caseID,
		Sequence:               seq,
		CommitID:               commitID,
		ParentCommitID:         parent,
		SnapshotID:             snapshotID,
		SnapshotManifestSHA256: manifestSHA,
		CommittedAt:            committedAt,
		Reason:                 reason,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return commitRecord{}, nil, err
	}
	return rec, raw, nil
}

// computeCommitID hashes the canonical commit body without commit_id.
func computeCommitID(caseID string, seq uint64, parent *string, snapshotID, manifestSHA, committedAt, reason string) (string, error) {
	body := struct {
		SchemaName             string  `json:"schema_name"`
		SchemaVersion          string  `json:"schema_version"`
		CaseID                 string  `json:"case_id"`
		Sequence               uint64  `json:"sequence"`
		ParentCommitID         *string `json:"parent_commit_id"`
		SnapshotID             string  `json:"snapshot_id"`
		SnapshotManifestSHA256 string  `json:"snapshot_manifest_sha256"`
		CommittedAt            string  `json:"committed_at"`
		Reason                 string  `json:"reason"`
	}{
		SchemaName:             schemaCommitRecord,
		SchemaVersion:          schemaVersion,
		CaseID:                 caseID,
		Sequence:               seq,
		ParentCommitID:         parent,
		SnapshotID:             snapshotID,
		SnapshotManifestSHA256: manifestSHA,
		CommittedAt:            committedAt,
		Reason:                 reason,
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "commit-" + hex.EncodeToString(sum[:])[:24], nil
}

func computeCommitIDFromRecord(rec commitRecord) (string, error) {
	return computeCommitID(rec.CaseID, rec.Sequence, rec.ParentCommitID, rec.SnapshotID, rec.SnapshotManifestSHA256, rec.CommittedAt, rec.Reason)
}

func parentString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
