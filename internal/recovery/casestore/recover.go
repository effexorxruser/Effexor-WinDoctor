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
		ReferencedFinalSnapshots:  []string{},
		BrokenTailSnapshots:       []string{},
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
	parseableFinals, malformedFinals, scanWarnings := s.scanParseableFinalCommits(caseID)
	for _, name := range malformedFinals {
		appendUniqueString(&ins.MalformedFinalCommits, name)
	}
	ins.Warnings = append(ins.Warnings, scanWarnings...)
	referencedFinals := map[string]struct{}{}
	for _, rec := range parseableFinals {
		referencedFinals[rec.SnapshotID] = struct{}{}
		appendUniqueString(&ins.ReferencedFinalSnapshots, rec.SnapshotID)
	}
	for _, name := range brokenTail {
		if rec, ok := parseableFinals[name]; ok {
			appendUniqueString(&ins.BrokenTailSnapshots, rec.SnapshotID)
		}
	}

	snapshotsRoot := s.snapshotsDir(caseID)
	if err := s.ensureManagedPath(snapshotsRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read snapshots: "+err.Error())
	} else if entries, err := os.ReadDir(snapshotsRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read snapshots: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			path := filepath.Join(snapshotsRoot, e.Name())
			if err := s.ensureManagedPath(path); err != nil {
				ins.Warnings = append(ins.Warnings, "read snapshots: "+err.Error())
				continue
			}
			if _, ok := committed[e.Name()]; ok {
				continue
			}
			if _, ok := referencedFinals[e.Name()]; ok {
				continue
			}
			manifest := filepath.Join(path, "snapshot-manifest.json")
			if _, err := os.Stat(manifest); os.IsNotExist(err) {
				ins.MissingManifests = append(ins.MissingManifests, e.Name())
			} else {
				ins.PublishedUncommitted = append(ins.PublishedUncommitted, e.Name())
			}
		}
	}

	stageRoot := s.stagingDir(caseID)
	if err := s.ensureManagedPath(stageRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read staging: "+err.Error())
	} else if entries, err := os.ReadDir(stageRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read staging: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			path := filepath.Join(stageRoot, e.Name())
			if err := s.ensureManagedPath(path); err != nil {
				ins.Warnings = append(ins.Warnings, "read staging: "+err.Error())
				continue
			}
			if e.IsDir() && isStagingTxnName(e.Name()) {
				ins.StagingTransactions = append(ins.StagingTransactions, e.Name())
			}
		}
	}

	commitsRoot := s.commitsDir(caseID)
	if err := s.ensureManagedPath(commitsRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read commits: "+err.Error())
	} else if entries, err := os.ReadDir(commitsRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "read commits: "+err.Error())
	} else if err == nil {
		for _, e := range entries {
			name := e.Name()
			path := filepath.Join(commitsRoot, name)
			if err := s.ensureManagedPath(path); err != nil {
				ins.Warnings = append(ins.Warnings, "read commits: "+err.Error())
				continue
			}
			if isTempStoreName(name) {
				ins.TemporaryCommitFiles = append(ins.TemporaryCommitFiles, name)
				continue
			}
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				appendUniqueString(&ins.MalformedFinalCommits, name)
				continue
			}
			var rec commitRecord
			if err := decodeStrict(raw, &rec); err != nil {
				appendUniqueString(&ins.MalformedFinalCommits, name)
				continue
			}
			if commitFileName(rec.Sequence, rec.CommitID) != name {
				appendUniqueString(&ins.MalformedFinalCommits, name)
			}
		}
	}

	refs := s.listReferencedBlobs(caseID, chain)
	artRoot := s.artifactsDir(caseID)
	if err := s.ensureManagedPath(artRoot); err != nil && !os.IsNotExist(err) {
		ins.Warnings = append(ins.Warnings, "walk artifacts: "+err.Error())
		return ins, nil
	}
	if err := filepath.Walk(artRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := s.ensureManagedPath(path); err != nil {
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
	if warnings, err := s.ensureCaseDirs(caseID); err != nil {
		return report, err
	} else {
		report.Warnings = append(report.Warnings, warnings...)
	}

	err := s.withCaseLock(caseID, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		snapshotsRoot := s.snapshotsDir(caseID)
		if err := s.ensureManagedPath(snapshotsRoot); err != nil && !os.IsNotExist(err) {
			report.Warnings = append(report.Warnings, "read snapshots: "+err.Error())
		} else if entries, err := os.ReadDir(snapshotsRoot); err == nil {
			for _, e := range entries {
				path := filepath.Join(snapshotsRoot, e.Name())
				if err := s.ensureManagedPath(path); err != nil {
					report.Warnings = append(report.Warnings, "read snapshots: "+err.Error())
					continue
				}
				if e.IsDir() {
					report.PreservedSnapshots = append(report.PreservedSnapshots, e.Name())
				}
			}
		} else if !os.IsNotExist(err) {
			report.Warnings = append(report.Warnings, "read snapshots: "+err.Error())
		}

		stageRoot := s.stagingDir(caseID)
		if err := s.ensureManagedPath(stageRoot); err != nil && !os.IsNotExist(err) {
			report.Warnings = append(report.Warnings, "read staging: "+err.Error())
			return nil
		}
		entries, err := os.ReadDir(stageRoot)
		if err != nil && !os.IsNotExist(err) {
			report.Warnings = append(report.Warnings, "read staging: "+err.Error())
			return nil
		}
		for _, e := range entries {
			path := filepath.Join(stageRoot, e.Name())
			if err := s.ensureManagedPath(path); err != nil {
				report.Warnings = append(report.Warnings, "read staging: "+err.Error())
				continue
			}
			if !e.IsDir() || !isStagingTxnName(e.Name()) {
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
			if err := s.ensureManagedPath(root); err != nil && !os.IsNotExist(err) {
				report.Warnings = append(report.Warnings, "walk temporary files: "+err.Error())
				continue
			}
			_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					report.Warnings = append(report.Warnings, "walk temporary files: "+walkErr.Error())
					return nil
				}
				if info == nil {
					report.Warnings = append(report.Warnings, "walk temporary files: missing file info for "+path)
					return nil
				}
				if err := s.ensureManagedPath(path); err != nil {
					report.Warnings = append(report.Warnings, "walk temporary files: "+err.Error())
					return nil
				}
				if info.IsDir() {
					return nil
				}
				if !isTempStoreName(info.Name()) {
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

func (s *Store) scanParseableFinalCommits(caseID string) (map[string]commitRecord, []string, []string) {
	dir := s.commitsDir(caseID)
	if err := s.ensureManagedPath(dir); err != nil {
		if os.IsNotExist(err) {
			return map[string]commitRecord{}, nil, nil
		}
		return map[string]commitRecord{}, nil, []string{"read commits: " + err.Error()}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]commitRecord{}, nil, nil
		}
		return map[string]commitRecord{}, nil, []string{"read commits: " + err.Error()}
	}
	parseable := map[string]commitRecord{}
	var malformed []string
	var warnings []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || isTempStoreName(name) || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := s.ensureManagedPath(path); err != nil {
			warnings = append(warnings, "read commits: "+err.Error())
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			malformed = append(malformed, name)
			continue
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
		if commitFileName(rec.Sequence, rec.CommitID) != name {
			malformed = append(malformed, name)
			continue
		}
		parseable[name] = rec
	}
	return parseable, malformed, warnings
}

func appendUniqueString(dst *[]string, value string) {
	for _, existing := range *dst {
		if existing == value {
			return
		}
	}
	*dst = append(*dst, value)
}
