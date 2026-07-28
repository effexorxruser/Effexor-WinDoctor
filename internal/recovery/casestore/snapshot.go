package casestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

// Validate checks Snapshot domain invariants before commit.
func (s Snapshot) Validate() error {
	if err := s.Case.Validate(); err != nil {
		return fmt.Errorf("case: %w", err)
	}
	if len(s.Targets) == 0 {
		return fmt.Errorf("%w: targets must not be empty", ErrInvalidArgument)
	}
	if len(s.EvidenceBundles) == 0 {
		return fmt.Errorf("%w: evidence_bundles must not be empty", ErrInvalidArgument)
	}

	created, err := time.Parse(time.RFC3339, s.Case.CreatedAt)
	if err != nil {
		return fmt.Errorf("case.created_at: %w", err)
	}
	updated, err := time.Parse(time.RFC3339, s.Case.UpdatedAt)
	if err != nil {
		return fmt.Errorf("case.updated_at: %w", err)
	}
	if updated.Before(created) {
		return fmt.Errorf("%w: updated_at must not be before created_at", ErrInvalidArgument)
	}

	targetIDs := make(map[string]struct{}, len(s.Targets))
	for i, t := range s.Targets {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		if _, ok := targetIDs[t.TargetID]; ok {
			return fmt.Errorf("%w: duplicate target_id %q", ErrInvalidArgument, t.TargetID)
		}
		targetIDs[t.TargetID] = struct{}{}
	}

	caseTargetSet := make(map[string]struct{}, len(s.Case.TargetIDs))
	for _, id := range s.Case.TargetIDs {
		caseTargetSet[id] = struct{}{}
	}
	if len(caseTargetSet) != len(targetIDs) {
		return fmt.Errorf("%w: case.target_ids does not match targets set", ErrInvalidArgument)
	}
	for id := range targetIDs {
		if _, ok := caseTargetSet[id]; !ok {
			return fmt.Errorf("%w: target %q missing from case.target_ids", ErrInvalidArgument, id)
		}
	}
	for id := range caseTargetSet {
		if _, ok := targetIDs[id]; !ok {
			return fmt.Errorf("%w: case.target_ids entry %q has no target document", ErrInvalidArgument, id)
		}
	}

	evidenceIDs := make(map[string]struct{}, len(s.EvidenceBundles))
	artifactByID := make(map[string]domain.ArtifactRef)
	refs := domain.NewCrossRefs(
		[]string{s.Case.CaseID},
		keys(targetIDs),
		nil, nil, nil, nil,
	)

	for i, e := range s.EvidenceBundles {
		if err := e.ValidateEvidenceRefs(refs); err != nil {
			return fmt.Errorf("evidence_bundles[%d]: %w", i, err)
		}
		if e.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: evidence_bundles[%d].case_id mismatch", ErrInvalidArgument, i)
		}
		if _, ok := evidenceIDs[e.EvidenceID]; ok {
			return fmt.Errorf("%w: duplicate evidence_id %q", ErrInvalidArgument, e.EvidenceID)
		}
		evidenceIDs[e.EvidenceID] = struct{}{}
		for j, a := range e.Artifacts {
			if err := rejectTraversal(a.RelativePath); err != nil {
				return fmt.Errorf("evidence_bundles[%d].artifacts[%d]: %w", i, j, err)
			}
			if prev, ok := artifactByID[a.ArtifactID]; ok {
				if !artifactRefsEqual(prev, a) {
					return fmt.Errorf("%w: divergent metadata for artifact_id %q", ErrInvalidArgument, a.ArtifactID)
				}
			} else {
				artifactByID[a.ArtifactID] = a
			}
		}
	}
	return nil
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func artifactRefsEqual(a, b domain.ArtifactRef) bool {
	return a.ArtifactID == b.ArtifactID &&
		a.Kind == b.Kind &&
		a.RelativePath == b.RelativePath &&
		strings.EqualFold(a.SHA256, b.SHA256) &&
		a.SizeBytes == b.SizeBytes &&
		a.CreatedAt == b.CreatedAt &&
		a.MediaClassification == b.MediaClassification
}

// SnapshotFromImporterResult converts a legacy importer Result into a Snapshot.
func SnapshotFromImporterResult(result legacyreport.Result) Snapshot {
	return Snapshot{
		Case:            result.Case,
		Targets:         append([]domain.Target(nil), result.Targets...),
		EvidenceBundles: append([]domain.EvidenceBundle(nil), result.EvidenceBundles...),
	}
}

type preparedDocument struct {
	RelativePath string
	MediaType    string
	Bytes        []byte
	SHA256       string
	SizeBytes    int64
}

func prepareDocuments(snap Snapshot) ([]preparedDocument, error) {
	var docs []preparedDocument

	caseBytes, err := marshalCanonical(snap.Case)
	if err != nil {
		return nil, fmt.Errorf("marshal case-manifest: %w", err)
	}
	docs = append(docs, documentEntry("case-manifest.json", caseBytes))

	targets := append([]domain.Target(nil), snap.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })
	for _, t := range targets {
		if err := validateTargetID(t.TargetID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(t)
		if err != nil {
			return nil, fmt.Errorf("marshal target %s: %w", t.TargetID, err)
		}
		docs = append(docs, documentEntry("targets/"+t.TargetID+".json", raw))
	}

	bundles := append([]domain.EvidenceBundle(nil), snap.EvidenceBundles...)
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].EvidenceID < bundles[j].EvidenceID })
	for _, e := range bundles {
		if err := validateEvidenceID(e.EvidenceID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(e)
		if err != nil {
			return nil, fmt.Errorf("marshal evidence %s: %w", e.EvidenceID, err)
		}
		docs = append(docs, documentEntry("evidence/"+e.EvidenceID+".json", raw))
	}

	sort.Slice(docs, func(i, j int) bool { return docs[i].RelativePath < docs[j].RelativePath })
	return docs, nil
}

func documentEntry(rel string, raw []byte) preparedDocument {
	sum := sha256.Sum256(raw)
	return preparedDocument{
		RelativePath: rel,
		MediaType:    mediaTypeJSON,
		Bytes:        raw,
		SHA256:       hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(raw)),
	}
}

func marshalCanonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

func collectArtifactRefs(snap Snapshot) ([]domain.ArtifactRef, error) {
	byID := make(map[string]domain.ArtifactRef)
	var order []string
	for _, e := range snap.EvidenceBundles {
		for _, a := range e.Artifacts {
			if err := validateArtifactID(a.ArtifactID); err != nil {
				return nil, err
			}
			if err := validateSHA256Hex(strings.ToLower(a.SHA256)); err != nil {
				return nil, err
			}
			a.SHA256 = strings.ToLower(a.SHA256)
			if prev, ok := byID[a.ArtifactID]; ok {
				if !artifactRefsEqual(prev, a) {
					return nil, fmt.Errorf("%w: divergent metadata for artifact_id %q", ErrInvalidArgument, a.ArtifactID)
				}
				continue
			}
			byID[a.ArtifactID] = a
			order = append(order, a.ArtifactID)
		}
	}
	sort.Strings(order)
	out := make([]domain.ArtifactRef, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

func buildSnapshotManifest(caseID string, createdAt string, docs []preparedDocument, arts []snapshotArtifactEntry) (snapshotManifest, []byte, error) {
	docEntries := make([]snapshotDocumentEntry, 0, len(docs))
	for _, d := range docs {
		docEntries = append(docEntries, snapshotDocumentEntry{
			RelativePath: d.RelativePath,
			SHA256:       d.SHA256,
			SizeBytes:    d.SizeBytes,
			MediaType:    d.MediaType,
		})
	}
	sort.Slice(docEntries, func(i, j int) bool { return docEntries[i].RelativePath < docEntries[j].RelativePath })
	if docEntries == nil {
		docEntries = []snapshotDocumentEntry{}
	}
	artsCopy := append([]snapshotArtifactEntry(nil), arts...)
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
		CaseID:        caseID,
		CreatedAt:     createdAt,
		Documents:     docEntries,
		Artifacts:     artsCopy,
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		return snapshotManifest{}, nil, err
	}
	sum := sha256.Sum256(canonical)
	contentSHA := hex.EncodeToString(sum[:])
	snapshotID := "snapshot-" + contentSHA[:24]

	manifest := snapshotManifest{
		SchemaName:    schemaSnapshotManifest,
		SchemaVersion: schemaVersion,
		CaseID:        caseID,
		SnapshotID:    snapshotID,
		ContentSHA256: contentSHA,
		CreatedAt:     createdAt,
		Documents:     docEntries,
		Artifacts:     artsCopy,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return snapshotManifest{}, nil, err
	}
	return manifest, raw, nil
}

func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON content")
		}
		return err
	}
	return nil
}
