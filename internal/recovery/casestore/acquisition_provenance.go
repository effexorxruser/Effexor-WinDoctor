package casestore

import (
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// validateAcquisitionCommitProvenance checks that each EvidenceAcquisitionRecord
// references a real ancestor commit and that input/added evidence IDs match the
// transition from that source commit snapshot.
//
// Snapshots without acquisitions are accepted unchanged (PR #17 compatibility).
// Workflow revision is not required to equal physical commit sequence.
//
// currentIdx is the index of the commit being validated in chain, or len(chain)
// when validating a not-yet-appended successor snapshot.
func (s *Store) validateAcquisitionCommitProvenance(caseID string, chain []commitRecord, currentIdx int, snap Snapshot) error {
	if len(snap.EvidenceAcquisitions) == 0 {
		return nil
	}
	byID := make(map[string]commitRecord, len(chain))
	indexOf := make(map[string]int, len(chain))
	for i, c := range chain {
		byID[c.CommitID] = c
		indexOf[c.CommitID] = i
	}
	for _, acq := range snap.EvidenceAcquisitions {
		src, ok := byID[acq.SourceCommitID]
		if !ok {
			return fmt.Errorf("%w: acquisition %q source_commit_id %q is not in commit chain",
				ErrIntegrity, acq.AcquisitionID, acq.SourceCommitID)
		}
		srcIdx := indexOf[acq.SourceCommitID]
		if srcIdx >= currentIdx {
			return fmt.Errorf("%w: acquisition %q source_commit_id %q is not an ancestor of the validated commit",
				ErrIntegrity, acq.AcquisitionID, acq.SourceCommitID)
		}
		sourceSnap, err := s.loadSnapshotAtCommit(caseID, src)
		if err != nil {
			return fmt.Errorf("%w: load source commit %s for acquisition %q: %v",
				ErrIntegrity, acq.SourceCommitID, acq.AcquisitionID, err)
		}
		sourceEvidence := evidenceIDSet(sourceSnap.EvidenceBundles)
		sourceTargets := targetIDSet(sourceSnap.Targets)
		for _, id := range acq.InputEvidenceIDs {
			if _, ok := sourceEvidence[id]; !ok {
				return fmt.Errorf("%w: acquisition %q input evidence %q absent from source commit %s",
					ErrIntegrity, acq.AcquisitionID, id, acq.SourceCommitID)
			}
		}
		for _, id := range acq.AddedEvidenceIDs {
			if _, ok := sourceEvidence[id]; ok {
				return fmt.Errorf("%w: acquisition %q added evidence %q already present in source commit %s",
					ErrIntegrity, acq.AcquisitionID, id, acq.SourceCommitID)
			}
			if findEvidenceByID(snap.EvidenceBundles, id) == nil {
				return fmt.Errorf("%w: acquisition %q added evidence %q missing from resulting snapshot",
					ErrIntegrity, acq.AcquisitionID, id)
			}
		}
		for _, id := range acq.AddedTargetIDs {
			if _, ok := sourceTargets[id]; ok {
				return fmt.Errorf("%w: acquisition %q added target %q already present in source commit %s",
					ErrIntegrity, acq.AcquisitionID, id, acq.SourceCommitID)
			}
			if findTargetByID(snap.Targets, id) == nil {
				return fmt.Errorf("%w: acquisition %q added target %q missing from resulting snapshot",
					ErrIntegrity, acq.AcquisitionID, id)
			}
		}
	}
	return nil
}

func evidenceIDSet(bundles []domain.EvidenceBundle) map[string]struct{} {
	out := make(map[string]struct{}, len(bundles))
	for _, e := range bundles {
		out[e.EvidenceID] = struct{}{}
	}
	return out
}

func targetIDSet(targets []domain.Target) map[string]struct{} {
	out := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		out[t.TargetID] = struct{}{}
	}
	return out
}

func indexOfCommit(chain []commitRecord, commitID string) int {
	for i, c := range chain {
		if c.CommitID == commitID {
			return i
		}
	}
	return -1
}
