package casestore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// InspectRecovery classifies case store objects for recovery tooling (read-only).
func (s *Store) InspectRecovery(ctx context.Context, caseID string) (RecoveryInspection, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryInspection{}, err
	}
	if err := validateCaseID(caseID); err != nil {
		return RecoveryInspection{}, err
	}

	ins := RecoveryInspection{
		CaseID:                    caseID,
		InspectedAt:               formatTime(s.clock.Now()),
		ValidCommittedSnapshots:   []string{},
		ValidCommitIDs:            []string{},
		StagingTransactions:       []string{},
		TemporaryCommitFiles:      []string{},
		PublishedUncommitted:      []string{},
		UnreferencedArtifactBlobs: []string{},
		MalformedFinalCommits:     []string{},
		BrokenCommitTail:          []string{},
		MissingManifests:          []string{},
		HashMismatches:            []string{},
		Warnings:                  []string{},
	}

	if err := s.ensureCaseTreeSafe(caseID); err != nil {
		ins.BrokenCommitChain = true
		ins.Warnings = append(ins.Warnings, err.Error())
		return ins, nil
	}

	chain, brokenTail, err := s.loadCommitChainPrefix(caseID)
	if err != nil {
		ins.BrokenCommitChain = true
		ins.BrokenCommitTail = append(ins.BrokenCommitTail, brokenTail...)
		ins.Warnings = append(ins.Warnings, err.Error())
		// Still continue to classify filesystem objects using the valid prefix.
	} else if len(brokenTail) > 0 {
		ins.BrokenCommitTail = append(ins.BrokenCommitTail, brokenTail...)
	}

	// Committed IDs come from the valid prefix only.
	committed := map[string]struct{}{}
	for _, c := range chain {
		committed[c.SnapshotID] = struct{}{}
		ins.ValidCommitIDs = append(ins.ValidCommitIDs, c.CommitID)
		if _, err := s.loadSnapshotAtCommit(caseID, c); err != nil {
			ins.HashMismatches = append(ins.HashMismatches, c.SnapshotID+": "+err.Error())
			continue
		}
		ins.ValidCommittedSnapshots = append(ins.ValidCommittedSnapshots, c.SnapshotID)
	}

	if entries, err := os.ReadDir(s.snapshotsDir(caseID)); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read snapshots: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, ok := committed[e.Name()]; ok {
				continue
			}
			manifest := filepath.Join(s.snapshotDir(caseID, e.Name()), "snapshot-manifest.json")
			if _, err := os.Stat(manifest); os.IsNotExist(err) {
				ins.MissingManifests = append(ins.MissingManifests, e.Name())
			} else {
				ins.PublishedUncommitted = append(ins.PublishedUncommitted, e.Name())
			}
		}
	}

	if entries, err := os.ReadDir(s.stagingDir(caseID)); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read staging: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			ins.StagingTransactions = append(ins.StagingTransactions, e.Name())
		}
	}

	if entries, err := os.ReadDir(s.commitsDir(caseID)); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read commits: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			name := e.Name()
			if isTempStoreName(name) {
				ins.TemporaryCommitFiles = append(ins.TemporaryCommitFiles, name)
				continue
			}
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			path := filepath.Join(s.commitsDir(caseID), name)
			raw, err := os.ReadFile(path)
			if err != nil {
				ins.MalformedFinalCommits = append(ins.MalformedFinalCommits, name)
				continue
			}
			var rec commitRecord
			if err := decodeStrict(raw, &rec); err != nil {
				ins.MalformedFinalCommits = append(ins.MalformedFinalCommits, name)
				continue
			}
			if commitFileName(rec.Sequence, rec.CommitID) != name {
				ins.MalformedFinalCommits = append(ins.MalformedFinalCommits, name)
			}
		}
	}

	refs := s.listReferencedBlobs(caseID, chain)
	if err := filepath.Walk(s.artifactsDir(caseID), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if isTempStoreName(info.Name()) {
			return nil
		}
		if !reSHA256.MatchString(info.Name()) {
			return nil
		}
		if _, ok := refs[info.Name()]; !ok {
			ins.UnreferencedArtifactBlobs = append(ins.UnreferencedArtifactBlobs, trimCaseRel(s.caseDir(caseID), path))
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "walk artifacts: "+err.Error())
	}

	return ins, nil
}

// CleanupStaging removes only staging transaction directories and temporary files
// with the reserved store suffix. It never deletes committed snapshots, orphan
// published snapshots, content-addressed artifacts, or malformed final commits.
func (s *Store) CleanupStaging(ctx context.Context, caseID string) (CleanupReport, error) {
	if err := ctx.Err(); err != nil {
		return CleanupReport{}, err
	}
	if err := validateCaseID(caseID); err != nil {
		return CleanupReport{}, err
	}
	if err := s.ensureCaseTreeSafe(caseID); err != nil {
		return CleanupReport{}, err
	}

	report := CleanupReport{
		CaseID:             caseID,
		RemovedStaging:     []string{},
		RemovedTemporary:   []string{},
		PreservedSnapshots: []string{},
		Warnings:           []string{},
	}

	err := s.withCaseLock(caseID, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entries, err := os.ReadDir(s.snapshotsDir(caseID)); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					report.PreservedSnapshots = append(report.PreservedSnapshots, e.Name())
				}
			}
		}

		stageRoot := s.stagingDir(caseID)
		entries, err := os.ReadDir(stageRoot)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, e := range entries {
			path := filepath.Join(stageRoot, e.Name())
			if err := s.ensureUnderRoot(path); err != nil {
				report.Warnings = append(report.Warnings, err.Error())
				continue
			}
			if err := os.RemoveAll(path); err != nil {
				report.Warnings = append(report.Warnings, err.Error())
				continue
			}
			report.RemovedStaging = append(report.RemovedStaging, e.Name())
		}

		// Temporary files under commits/ and artifacts/.
		roots := []string{s.commitsDir(caseID), filepath.Join(s.caseDir(caseID), "artifacts")}
		for _, root := range roots {
			_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil || info == nil || info.IsDir() {
					return nil
				}
				if !isTempStoreName(info.Name()) {
					return nil
				}
				if err := s.ensureUnderRoot(path); err != nil {
					report.Warnings = append(report.Warnings, err.Error())
					return nil
				}
				if err := os.Remove(path); err != nil {
					report.Warnings = append(report.Warnings, err.Error())
					return nil
				}
				report.RemovedTemporary = append(report.RemovedTemporary, trimCaseRel(s.caseDir(caseID), path))
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	return report, nil
}
