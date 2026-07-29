package casestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

	var lastSeq uint64
	var lastCommitID, lastSnapshotID string
	for i, c := range chain {
		snap, err := s.loadSnapshotAtCommit(caseID, c)
		if err != nil {
			msg := "committed state is corrupt; refusing automatic fallback"
			if i == len(chain)-1 {
				msg = "latest committed state is corrupt; refusing automatic fallback"
			}
			return Snapshot{}, CommitInfo{}, &IntegrityError{
				CaseID:              caseID,
				Message:             msg,
				LastValidSequence:   lastSeq,
				LastValidCommitID:   lastCommitID,
				LastValidSnapshotID: lastSnapshotID,
				Cause:               err,
			}
		}
		lastSeq = c.Sequence
		lastCommitID = c.CommitID
		lastSnapshotID = c.SnapshotID
		if i == len(chain)-1 {
			return snap, CommitInfo{
				CaseID:         caseID,
				SnapshotID:     c.SnapshotID,
				CommitID:       c.CommitID,
				Sequence:       c.Sequence,
				ParentCommitID: parentString(c.ParentCommitID),
				CommittedAt:    c.CommittedAt,
				Idempotent:     false,
			}, nil
		}
	}
	return Snapshot{}, CommitInfo{}, fmt.Errorf("%w: %s", ErrCaseNotFound, caseID)
}

func (s *Store) loadSnapshotAtCommit(caseID string, head commitRecord) (Snapshot, error) {
	if err := validateSnapshotID(head.SnapshotID); err != nil {
		return Snapshot{}, err
	}
	snapDir := s.snapshotDir(caseID, head.SnapshotID)
	if err := s.ensureManagedPath(snapDir); err != nil {
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
	if err := s.ensureManagedPath(docsDir); err != nil {
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
		if err := s.ensureManagedPath(path); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
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
	snap.Normalize()
	caseRaw, err := os.ReadFile(filepath.Join(docsDir, "case-manifest.json"))
	if err != nil {
		return Snapshot{}, err
	}
	if err := domain.DecodeAndValidateJSON(caseRaw, &snap.Case); err != nil {
		return Snapshot{}, fmt.Errorf("case-manifest: %w", err)
	}

	for _, d := range manifest.Documents {
		switch {
		case d.RelativePath == "case-manifest.json":
			continue
		case d.RelativePath == "case-workflow-state.json":
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var w domain.CaseWorkflowState
			if err := domain.DecodeAndValidateJSON(raw, &w); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			snap.WorkflowState = &w
		case strings.HasPrefix(d.RelativePath, "targets/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var t domain.Target
			if err := domain.DecodeAndValidateJSON(raw, &t); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			want := "targets/" + t.TargetID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: target path %q does not match target_id %q", ErrIntegrity, d.RelativePath, t.TargetID)
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
			want := "evidence/" + e.EvidenceID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: evidence path %q does not match evidence_id %q", ErrIntegrity, d.RelativePath, e.EvidenceID)
			}
			snap.EvidenceBundles = append(snap.EvidenceBundles, e)
		case strings.HasPrefix(d.RelativePath, "findings/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var f domain.Finding
			if err := domain.DecodeAndValidateJSON(raw, &f); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			want := "findings/" + f.FindingID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: finding path %q does not match finding_id %q", ErrIntegrity, d.RelativePath, f.FindingID)
			}
			snap.Findings = append(snap.Findings, f)
		case strings.HasPrefix(d.RelativePath, "plans/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var p domain.RepairPlan
			if err := domain.DecodeAndValidateJSON(raw, &p); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			want := "plans/" + p.PlanID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: plan path %q does not match plan_id %q", ErrIntegrity, d.RelativePath, p.PlanID)
			}
			snap.RepairPlans = append(snap.RepairPlans, p)
		case strings.HasPrefix(d.RelativePath, "executions/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var e domain.ExecutionEvent
			if err := domain.DecodeAndValidateJSON(raw, &e); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			want := "executions/" + e.ExecutionID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: execution path %q does not match execution_id %q", ErrIntegrity, d.RelativePath, e.ExecutionID)
			}
			snap.ExecutionEvents = append(snap.ExecutionEvents, e)
		case strings.HasPrefix(d.RelativePath, "verifications/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var v domain.VerificationReport
			if err := domain.DecodeAndValidateJSON(raw, &v); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			want := "verifications/" + v.VerificationID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: verification path %q does not match verification_id %q", ErrIntegrity, d.RelativePath, v.VerificationID)
			}
			snap.VerificationReports = append(snap.VerificationReports, v)
		case strings.HasPrefix(d.RelativePath, "coordinator-events/") && strings.HasSuffix(d.RelativePath, ".json"):
			raw, err := os.ReadFile(filepath.Join(docsDir, filepath.FromSlash(d.RelativePath)))
			if err != nil {
				return Snapshot{}, err
			}
			var ev domain.CoordinatorEvent
			if err := domain.DecodeAndValidateJSON(raw, &ev); err != nil {
				return Snapshot{}, fmt.Errorf("%s: %w", d.RelativePath, err)
			}
			want := "coordinator-events/" + ev.EventID + ".json"
			if d.RelativePath != want {
				return Snapshot{}, fmt.Errorf("%w: coordinator-event path %q does not match event_id %q", ErrIntegrity, d.RelativePath, ev.EventID)
			}
			snap.CoordinatorEvents = append(snap.CoordinatorEvents, ev)
		default:
			return Snapshot{}, fmt.Errorf("%w: unsupported document path %q", ErrIntegrity, d.RelativePath)
		}
	}
	sort.Slice(snap.Targets, func(i, j int) bool { return snap.Targets[i].TargetID < snap.Targets[j].TargetID })
	sort.Slice(snap.EvidenceBundles, func(i, j int) bool {
		return snap.EvidenceBundles[i].EvidenceID < snap.EvidenceBundles[j].EvidenceID
	})
	sort.Slice(snap.Findings, func(i, j int) bool { return snap.Findings[i].FindingID < snap.Findings[j].FindingID })
	sort.Slice(snap.RepairPlans, func(i, j int) bool { return snap.RepairPlans[i].PlanID < snap.RepairPlans[j].PlanID })
	sort.Slice(snap.ExecutionEvents, func(i, j int) bool {
		return snap.ExecutionEvents[i].ExecutionID < snap.ExecutionEvents[j].ExecutionID
	})
	sort.Slice(snap.VerificationReports, func(i, j int) bool {
		return snap.VerificationReports[i].VerificationID < snap.VerificationReports[j].VerificationID
	})
	sort.Slice(snap.CoordinatorEvents, func(i, j int) bool {
		return snap.CoordinatorEvents[i].EventID < snap.CoordinatorEvents[j].EventID
	})
	if err := snap.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := compareManifestArtifacts(manifest, snap); err != nil {
		return Snapshot{}, err
	}
	if err := compareCanonicalDocuments(manifest, snap); err != nil {
		return Snapshot{}, err
	}

	for _, a := range manifest.Artifacts {
		blob := s.blobAbsPath(caseID, a.SHA256)
		if err := s.ensureManagedPath(filepath.Dir(blob)); err != nil {
			return Snapshot{}, err
		}
		if err := s.ensureManagedPath(blob); err != nil {
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
	caseManifestCount := 0
	for i, d := range m.Documents {
		if err := rejectTraversal(d.RelativePath); err != nil {
			return fmt.Errorf("%w: documents[%d].relative_path: %v", ErrIntegrity, i, err)
		}
		if err := validateManifestDocumentPath(d.RelativePath); err != nil {
			return fmt.Errorf("%w: documents[%d]: %v", ErrIntegrity, i, err)
		}
		if d.RelativePath == "case-manifest.json" {
			caseManifestCount++
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
	if caseManifestCount != 1 {
		return fmt.Errorf("%w: expected exactly one case-manifest.json, got %d", ErrIntegrity, caseManifestCount)
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

func validateManifestDocumentPath(rel string) error {
	if rel == "case-manifest.json" || rel == "case-workflow-state.json" {
		return nil
	}
	type prefixRule struct {
		prefix string
		re     *regexp.Regexp
		label  string
	}
	rules := []prefixRule{
		{"targets/", reTargetID, "target"},
		{"evidence/", reEvidenceID, "evidence"},
		{"findings/", reFindingID, "finding"},
		{"plans/", rePlanID, "plan"},
		{"executions/", reExecutionID, "execution"},
		{"verifications/", reVerificationID, "verification"},
		{"coordinator-events/", reCoordinatorEventID, "coordinator-event"},
	}
	for _, rule := range rules {
		if strings.HasPrefix(rel, rule.prefix) && strings.HasSuffix(rel, ".json") {
			id := strings.TrimSuffix(strings.TrimPrefix(rel, rule.prefix), ".json")
			if rule.re.MatchString(id) && !strings.Contains(id, "/") {
				return nil
			}
			return fmt.Errorf("%w: non-canonical %s document path %q", ErrIntegrity, rule.label, rel)
		}
	}
	return fmt.Errorf("%w: non-canonical document path %q", ErrIntegrity, rel)
}

func compareCanonicalDocuments(manifest snapshotManifest, snap Snapshot) error {
	docs, err := prepareDocuments(snap)
	if err != nil {
		return err
	}
	if len(docs) != len(manifest.Documents) {
		return fmt.Errorf("%w: canonical document count %d != manifest %d", ErrIntegrity, len(docs), len(manifest.Documents))
	}
	caseManifestCount := 0
	for i, d := range docs {
		m := manifest.Documents[i]
		if d.RelativePath != m.RelativePath || d.SHA256 != m.SHA256 || d.SizeBytes != m.SizeBytes || d.MediaType != m.MediaType {
			return fmt.Errorf("%w: canonical document mismatch at %q", ErrIntegrity, d.RelativePath)
		}
		if d.RelativePath == "case-manifest.json" {
			caseManifestCount++
		}
	}
	if caseManifestCount != 1 {
		return fmt.Errorf("%w: expected exactly one case-manifest.json, got %d", ErrIntegrity, caseManifestCount)
	}
	return nil
}

type loadedCommit struct {
	record commitRecord
	path   string
}

func (s *Store) loadCommitChain(caseID string) ([]commitRecord, error) {
	valid, _, err := s.loadCommitChainPrefix(caseID)
	if err != nil {
		return nil, err
	}
	return valid, nil
}

// loadCommitChainPrefix returns the longest valid commit prefix, any broken/malformed
// tail filenames, and a non-nil error when the chain is incomplete or corrupt.
func (s *Store) loadCommitChainPrefix(caseID string) (valid []commitRecord, brokenTail []string, err error) {
	dir := s.commitsDir(caseID)
	if err := s.ensureManagedPath(dir); err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	var loaded []loadedCommit
	var malformed []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || isTempStoreName(name) || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := s.ensureManagedPath(path); err != nil {
			return nil, nil, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, &IntegrityError{CaseID: caseID, Message: "failed reading commit", Cause: err}
		}
		var rec commitRecord
		if err := decodeStrict(raw, &rec); err != nil {
			malformed = append(malformed, name)
			continue
		}
		if err := validateCommitRecord(rec, caseID); err != nil {
			malformed = append(malformed, name)
			continue
		}
		wantName := commitFileName(rec.Sequence, rec.CommitID)
		if name != wantName {
			malformed = append(malformed, name)
			continue
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
			for _, rem := range loaded[i:] {
				brokenTail = append(brokenTail, filepath.Base(rem.path))
			}
			brokenTail = append(brokenTail, malformed...)
			var lastCommitID, lastSnapshotID string
			if len(out) > 0 {
				prev := out[len(out)-1]
				lastCommitID = prev.CommitID
				lastSnapshotID = prev.SnapshotID
			}
			return out, brokenTail, &IntegrityError{
				CaseID:              caseID,
				Message:             fmt.Sprintf("commit sequence gap: got %d want %d", rec.Sequence, wantSeq),
				LastValidSequence:   uint64(i),
				LastValidCommitID:   lastCommitID,
				LastValidSnapshotID: lastSnapshotID,
				Cause:               ErrIntegrity,
			}
		}
		if i == 0 {
			if rec.ParentCommitID != nil {
				for _, rem := range loaded[i:] {
					brokenTail = append(brokenTail, filepath.Base(rem.path))
				}
				brokenTail = append(brokenTail, malformed...)
				return nil, brokenTail, &IntegrityError{
					CaseID:  caseID,
					Message: "first commit must have null parent_commit_id",
					Cause:   ErrIntegrity,
				}
			}
		} else {
			prev := out[i-1]
			if rec.ParentCommitID == nil || *rec.ParentCommitID != prev.CommitID {
				for _, rem := range loaded[i:] {
					brokenTail = append(brokenTail, filepath.Base(rem.path))
				}
				brokenTail = append(brokenTail, malformed...)
				return out, brokenTail, &IntegrityError{
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

	if len(malformed) > 0 {
		brokenTail = append([]string(nil), malformed...)
		var lastSeq uint64
		var lastCommitID, lastSnapshotID string
		if len(out) > 0 {
			last := out[len(out)-1]
			lastSeq = last.Sequence
			lastCommitID = last.CommitID
			lastSnapshotID = last.SnapshotID
		}
		msg := "malformed final commit record " + malformed[0]
		return out, brokenTail, &IntegrityError{
			CaseID:              caseID,
			Message:             msg,
			LastValidSequence:   lastSeq,
			LastValidCommitID:   lastCommitID,
			LastValidSnapshotID: lastSnapshotID,
			Cause:               ErrIntegrity,
		}
	}
	return out, nil, nil
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
