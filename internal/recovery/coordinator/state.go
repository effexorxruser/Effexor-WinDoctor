package coordinator

import (
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func (c *Coordinator) appendEvent(snap *casestore.Snapshot, ev domain.CoordinatorEvent) {
	snap.CoordinatorEvents = append(append([]domain.CoordinatorEvent(nil), snap.CoordinatorEvents...), ev)
}

func (c *Coordinator) setWorkflow(snap *casestore.Snapshot, state domain.WorkflowStateName, eventID string, revision uint64, failure *domain.WorkflowFailure, activePlanID string) error {
	caseState, err := domain.CaseStateForWorkflow(state)
	if err != nil {
		return err
	}
	now := c.monotonicNow(snap)
	snap.Case.UpdatedAt = now
	snap.Case.CurrentState = caseState
	ws := &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           snap.Case.CaseID,
		State:            state,
		Revision:         revision,
		UpdatedAt:        now,
		LastTransitionID: eventID,
		ActivePlanID:     activePlanID,
		Failure:          failure,
	}
	snap.WorkflowState = ws
	return nil
}

// monotonicNow returns an RFC3339 timestamp not earlier than Case.CreatedAt,
// Case.UpdatedAt, or WorkflowState.UpdatedAt. WinPE wall clock is not trusted alone.
func (c *Coordinator) monotonicNow(snap *casestore.Snapshot) string {
	now := c.clock.Now().UTC()
	candidates := []time.Time{now}
	for _, raw := range []string{snap.Case.CreatedAt, snap.Case.UpdatedAt} {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			candidates = append(candidates, t.UTC())
		}
	}
	if snap.WorkflowState != nil {
		if t, err := time.Parse(time.RFC3339, snap.WorkflowState.UpdatedAt); err == nil {
			candidates = append(candidates, t.UTC())
		}
	}
	max := candidates[0]
	for _, t := range candidates[1:] {
		if t.After(max) {
			max = t
		}
	}
	return max.Format(time.RFC3339)
}

func copySnapshot(src casestore.Snapshot) casestore.Snapshot {
	dst := src
	dst.Targets = append([]domain.Target(nil), src.Targets...)
	dst.EvidenceBundles = append([]domain.EvidenceBundle(nil), src.EvidenceBundles...)
	dst.Findings = append([]domain.Finding(nil), src.Findings...)
	dst.RepairPlans = append([]domain.RepairPlan(nil), src.RepairPlans...)
	dst.ExecutionEvents = append([]domain.ExecutionEvent(nil), src.ExecutionEvents...)
	dst.VerificationReports = append([]domain.VerificationReport(nil), src.VerificationReports...)
	dst.CoordinatorEvents = append([]domain.CoordinatorEvent(nil), src.CoordinatorEvents...)
	dst.EvidenceAcquisitions = append([]domain.EvidenceAcquisitionRecord(nil), src.EvidenceAcquisitions...)
	if src.WorkflowState != nil {
		ws := *src.WorkflowState
		if src.WorkflowState.Failure != nil {
			f := *src.WorkflowState.Failure
			ws.Failure = &f
		}
		dst.WorkflowState = &ws
	}
	return dst
}

func currentState(snap casestore.Snapshot) domain.WorkflowStateName {
	if snap.WorkflowState == nil {
		return ""
	}
	return snap.WorkflowState.State
}

func nextRevision(snap casestore.Snapshot) uint64 {
	if snap.WorkflowState == nil {
		return 1
	}
	return snap.WorkflowState.Revision + 1
}

func defaultActor(actor domain.ActorType, fallback domain.ActorType) domain.ActorType {
	if actor == "" {
		return fallback
	}
	return actor
}

func defaultReason(code, fallback string) string {
	if code == "" {
		return fallback
	}
	return code
}
