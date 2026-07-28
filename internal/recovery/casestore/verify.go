package casestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Verify performs a read-only integrity check of a case.
func (s *Store) Verify(ctx context.Context, caseID string) (IntegrityReport, error) {
	if err := ctx.Err(); err != nil {
		return IntegrityReport{}, err
	}
	if err := validateCaseID(caseID); err != nil {
		return IntegrityReport{}, err
	}

	report := IntegrityReport{
		CaseID:          caseID,
		CheckedAt:       formatTime(s.clock.Now()),
		StagingEntries:  []string{},
		OrphanSnapshots: []string{},
		OrphanArtifacts: []string{},
		TemporaryFiles:  []string{},
		Warnings:        []string{},
		Errors:          []string{},
		Status:          IntegrityOK,
	}

	if err := s.ensureCaseTreeSafe(caseID); err != nil {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, err.Error())
		return report, nil
	}

	if _, err := os.Stat(s.caseDir(caseID)); os.IsNotExist(err) {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, "case directory missing")
		return report, nil
	}

	chain, err := s.loadCommitChain(caseID)
	if err != nil {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, err.Error())
		return report, nil
	}
	report.CommitCount = len(chain)
	if len(chain) > 0 {
		report.LatestCommit = chain[len(chain)-1].CommitID
	}

	// Committed snapshot IDs come from the chain regardless of load success.
	committedSnaps := map[string]struct{}{}
	referencedBlobs := map[string]struct{}{}
	for _, c := range chain {
		committedSnaps[c.SnapshotID] = struct{}{}
		snap, err := s.loadSnapshotAtCommit(caseID, c)
		if err != nil {
			report.Status = IntegrityCorrupt
			report.Errors = append(report.Errors, fmt.Sprintf("commit %s: %v", c.CommitID, err))
			continue
		}
		_ = snap
		manifest, err := s.readManifest(caseID, c.SnapshotID)
		if err != nil {
			report.Status = IntegrityCorrupt
			report.Errors = append(report.Errors, err.Error())
			continue
		}
		report.VerifiedDocuments += len(manifest.Documents)
		report.VerifiedArtifacts += len(manifest.Artifacts)
		for _, a := range manifest.Artifacts {
			referencedBlobs[a.SHA256] = struct{}{}
		}
	}

	snapRoot := s.snapshotsDir(caseID)
	entries, err := os.ReadDir(snapRoot)
	if err != nil && !os.IsNotExist(err) {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, "read snapshots: "+err.Error())
	} else if err == nil {
		report.SnapshotCount = len(entries)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, ok := committedSnaps[e.Name()]; !ok {
				report.OrphanSnapshots = append(report.OrphanSnapshots, e.Name())
				report.Status = degrade(report.Status)
			}
		}
	}

	artRoot := s.artifactsDir(caseID)
	walkErr := filepath.Walk(artRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if isTempStoreName(name) {
			rel, _ := filepath.Rel(s.caseDir(caseID), path)
			report.TemporaryFiles = append(report.TemporaryFiles, filepath.ToSlash(rel))
			report.Status = degrade(report.Status)
			return nil
		}
		if !reSHA256.MatchString(name) {
			return nil
		}
		if _, ok := referencedBlobs[name]; !ok {
			rel, _ := filepath.Rel(s.caseDir(caseID), path)
			report.OrphanArtifacts = append(report.OrphanArtifacts, filepath.ToSlash(rel))
			report.Status = degrade(report.Status)
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, "walk artifacts: "+walkErr.Error())
	}

	stageRoot := s.stagingDir(caseID)
	if entries, err := os.ReadDir(stageRoot); err != nil && !os.IsNotExist(err) {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, "read staging: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			report.StagingEntries = append(report.StagingEntries, e.Name())
			report.Status = degrade(report.Status)
		}
	}

	commitsDir := s.commitsDir(caseID)
	if entries, err := os.ReadDir(commitsDir); err != nil && !os.IsNotExist(err) {
		report.Status = IntegrityCorrupt
		report.Errors = append(report.Errors, "read commits: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			if isTempStoreName(e.Name()) {
				report.TemporaryFiles = append(report.TemporaryFiles, "commits/"+e.Name())
				report.Status = degrade(report.Status)
			}
		}
	}

	return report, nil
}

func (s *Store) readManifest(caseID, snapshotID string) (snapshotManifest, error) {
	raw, err := os.ReadFile(filepath.Join(s.snapshotDir(caseID, snapshotID), "snapshot-manifest.json"))
	if err != nil {
		return snapshotManifest{}, err
	}
	var m snapshotManifest
	if err := decodeStrict(raw, &m); err != nil {
		return snapshotManifest{}, err
	}
	return m, nil
}

func degrade(s IntegrityStatus) IntegrityStatus {
	if s == IntegrityCorrupt {
		return s
	}
	return IntegrityDegraded
}

// listReferencedBlobs returns sha256 hex digests referenced by committed manifests.
func (s *Store) listReferencedBlobs(caseID string, chain []commitRecord) map[string]struct{} {
	out := map[string]struct{}{}
	for _, c := range chain {
		m, err := s.readManifest(caseID, c.SnapshotID)
		if err != nil {
			continue
		}
		for _, a := range m.Artifacts {
			out[a.SHA256] = struct{}{}
		}
	}
	return out
}

func trimCaseRel(caseDir, path string) string {
	rel, err := filepath.Rel(caseDir, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}
