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

// Normalize empties optional collections so nil and empty slices serialize
// identically when preparing documents (no documents written for empty sets).
func (s *Snapshot) Normalize() {
	if s.Findings == nil {
		s.Findings = []domain.Finding{}
	}
	if s.RepairPlans == nil {
		s.RepairPlans = []domain.RepairPlan{}
	}
	if s.ExecutionEvents == nil {
		s.ExecutionEvents = []domain.ExecutionEvent{}
	}
	if s.VerificationReports == nil {
		s.VerificationReports = []domain.VerificationReport{}
	}
	if s.CoordinatorEvents == nil {
		s.CoordinatorEvents = []domain.CoordinatorEvent{}
	}
	if s.EvidenceAcquisitions == nil {
		s.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{}
	}
	if s.AgentConsultations == nil {
		s.AgentConsultations = []domain.AgentConsultation{}
	}
	if s.PolicyEvaluations == nil {
		s.PolicyEvaluations = []domain.PolicyEvaluation{}
	}
	if s.RepairApprovals == nil {
		s.RepairApprovals = []domain.RepairApproval{}
	}
}

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
	if s.WorkflowState == nil {
		if len(s.Findings) > 0 || len(s.RepairPlans) > 0 || len(s.ExecutionEvents) > 0 ||
			len(s.VerificationReports) > 0 || len(s.CoordinatorEvents) > 0 ||
			len(s.EvidenceAcquisitions) > 0 || len(s.AgentConsultations) > 0 ||
			len(s.PolicyEvaluations) > 0 || len(s.RepairApprovals) > 0 {
			return fmt.Errorf("%w: lifecycle documents require workflow_state", ErrInvalidArgument)
		}
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
	for i, e := range s.EvidenceBundles {
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

	findingIDs := make(map[string]struct{}, len(s.Findings))
	for _, f := range s.Findings {
		if _, ok := findingIDs[f.FindingID]; ok {
			return fmt.Errorf("%w: duplicate finding_id %q", ErrInvalidArgument, f.FindingID)
		}
		findingIDs[f.FindingID] = struct{}{}
	}

	planIDs := make(map[string]struct{}, len(s.RepairPlans))
	for _, p := range s.RepairPlans {
		if _, ok := planIDs[p.PlanID]; ok {
			return fmt.Errorf("%w: duplicate plan_id %q", ErrInvalidArgument, p.PlanID)
		}
		planIDs[p.PlanID] = struct{}{}
	}

	executionIDs := make(map[string]struct{}, len(s.ExecutionEvents))
	for _, e := range s.ExecutionEvents {
		if _, ok := executionIDs[e.ExecutionID]; ok {
			return fmt.Errorf("%w: duplicate execution_id %q", ErrInvalidArgument, e.ExecutionID)
		}
		executionIDs[e.ExecutionID] = struct{}{}
	}

	verificationIDs := make(map[string]struct{}, len(s.VerificationReports))
	for _, v := range s.VerificationReports {
		if _, ok := verificationIDs[v.VerificationID]; ok {
			return fmt.Errorf("%w: duplicate verification_id %q", ErrInvalidArgument, v.VerificationID)
		}
		verificationIDs[v.VerificationID] = struct{}{}
	}

	eventIDs := make(map[string]struct{}, len(s.CoordinatorEvents))
	for _, ev := range s.CoordinatorEvents {
		if _, ok := eventIDs[ev.EventID]; ok {
			return fmt.Errorf("%w: duplicate coordinator event_id %q", ErrInvalidArgument, ev.EventID)
		}
		eventIDs[ev.EventID] = struct{}{}
	}

	acquisitionIDs := make(map[string]struct{}, len(s.EvidenceAcquisitions))
	requestIDs := make(map[string]struct{}, len(s.EvidenceAcquisitions))
	for i, acq := range s.EvidenceAcquisitions {
		if _, ok := acquisitionIDs[acq.AcquisitionID]; ok {
			return fmt.Errorf("%w: duplicate acquisition_id %q", ErrInvalidArgument, acq.AcquisitionID)
		}
		acquisitionIDs[acq.AcquisitionID] = struct{}{}
		if _, ok := requestIDs[acq.RequestID]; ok {
			return fmt.Errorf("%w: duplicate acquisition request_id %q", ErrInvalidArgument, acq.RequestID)
		}
		requestIDs[acq.RequestID] = struct{}{}
		if acq.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: evidence_acquisitions[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}

	consultationIDs := make(map[string]struct{}, len(s.AgentConsultations))
	consultationRequestIDs := make(map[string]struct{}, len(s.AgentConsultations))
	for i, cons := range s.AgentConsultations {
		if _, ok := consultationIDs[cons.ConsultationID]; ok {
			return fmt.Errorf("%w: duplicate consultation_id %q", ErrInvalidArgument, cons.ConsultationID)
		}
		consultationIDs[cons.ConsultationID] = struct{}{}
		if _, ok := consultationRequestIDs[cons.RequestID]; ok {
			return fmt.Errorf("%w: duplicate consultation request_id %q", ErrInvalidArgument, cons.RequestID)
		}
		consultationRequestIDs[cons.RequestID] = struct{}{}
		if cons.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: agent_consultations[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}

	policyIDs := make(map[string]struct{}, len(s.PolicyEvaluations))
	policyRequestIDs := make(map[string]struct{}, len(s.PolicyEvaluations))
	for i, pol := range s.PolicyEvaluations {
		if _, ok := policyIDs[pol.EvaluationID]; ok {
			return fmt.Errorf("%w: duplicate evaluation_id %q", ErrInvalidArgument, pol.EvaluationID)
		}
		policyIDs[pol.EvaluationID] = struct{}{}
		if _, ok := policyRequestIDs[pol.RequestID]; ok {
			return fmt.Errorf("%w: duplicate policy request_id %q", ErrInvalidArgument, pol.RequestID)
		}
		policyRequestIDs[pol.RequestID] = struct{}{}
		if pol.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: policy_evaluations[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}

	approvalIDs := make(map[string]struct{}, len(s.RepairApprovals))
	approvalRequestIDs := make(map[string]struct{}, len(s.RepairApprovals))
	for i, appr := range s.RepairApprovals {
		if _, ok := approvalIDs[appr.ApprovalID]; ok {
			return fmt.Errorf("%w: duplicate approval_id %q", ErrInvalidArgument, appr.ApprovalID)
		}
		approvalIDs[appr.ApprovalID] = struct{}{}
		if _, ok := approvalRequestIDs[appr.RequestID]; ok {
			return fmt.Errorf("%w: duplicate approval request_id %q", ErrInvalidArgument, appr.RequestID)
		}
		approvalRequestIDs[appr.RequestID] = struct{}{}
		if appr.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: repair_approvals[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}

	docIDs := make(map[string]struct{})
	docIDs[s.Case.CaseID] = struct{}{}
	for id := range targetIDs {
		docIDs[id] = struct{}{}
	}
	for id := range evidenceIDs {
		docIDs[id] = struct{}{}
	}
	for id := range findingIDs {
		docIDs[id] = struct{}{}
	}
	for id := range planIDs {
		docIDs[id] = struct{}{}
	}
	for id := range executionIDs {
		docIDs[id] = struct{}{}
	}
	for id := range verificationIDs {
		docIDs[id] = struct{}{}
	}
	for id := range eventIDs {
		docIDs[id] = struct{}{}
	}
	for id := range acquisitionIDs {
		docIDs[id] = struct{}{}
	}
	for id := range consultationIDs {
		docIDs[id] = struct{}{}
	}
	for id := range policyIDs {
		docIDs[id] = struct{}{}
	}
	for id := range approvalIDs {
		docIDs[id] = struct{}{}
	}
	if s.WorkflowState != nil {
		docIDs[domain.DocumentIDCaseWorkflowState] = struct{}{}
	}

	refs := domain.CrossRefs{
		CaseIDs:             setOf(s.Case.CaseID),
		TargetIDs:           targetIDs,
		EvidenceIDs:         evidenceIDs,
		FindingIDs:          findingIDs,
		PlanIDs:             planIDs,
		ExecutionIDs:        executionIDs,
		VerificationIDs:     verificationIDs,
		ArtifactIDs:         artifactIDSet(artifactByID),
		CoordinatorEventIDs: eventIDs,
		PolicyEvaluationIDs: policyIDs,
		RepairApprovalIDs:   approvalIDs,
		DocumentIDs:         docIDs,
	}

	for i, e := range s.EvidenceBundles {
		if err := e.ValidateEvidenceRefs(refs); err != nil {
			return fmt.Errorf("evidence_bundles[%d]: %w", i, err)
		}
	}
	for i, f := range s.Findings {
		if err := f.ValidateFindingRefs(refs); err != nil {
			return fmt.Errorf("findings[%d]: %w", i, err)
		}
		if f.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: findings[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, p := range s.RepairPlans {
		if err := p.ValidatePlanRefs(refs); err != nil {
			return fmt.Errorf("repair_plans[%d]: %w", i, err)
		}
		if p.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: repair_plans[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, e := range s.ExecutionEvents {
		if err := e.ValidateExecutionRefs(refs); err != nil {
			return fmt.Errorf("execution_events[%d]: %w", i, err)
		}
		if e.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: execution_events[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, v := range s.VerificationReports {
		if err := v.ValidateVerificationRefs(refs); err != nil {
			return fmt.Errorf("verification_reports[%d]: %w", i, err)
		}
		if v.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: verification_reports[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, ev := range s.CoordinatorEvents {
		if err := ev.ValidateCoordinatorEventRefs(refs); err != nil {
			return fmt.Errorf("coordinator_events[%d]: %w", i, err)
		}
		if ev.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: coordinator_events[%d].case_id mismatch", ErrInvalidArgument, i)
		}
		if err := validateCoordinatorEventReferenceSemantics(s, ev); err != nil {
			return fmt.Errorf("coordinator_events[%d]: %w", i, err)
		}
	}
	for i, acq := range s.EvidenceAcquisitions {
		if err := acq.ValidateAcquisitionRefs(refs); err != nil {
			return fmt.Errorf("evidence_acquisitions[%d]: %w", i, err)
		}
	}
	for i, cons := range s.AgentConsultations {
		if err := cons.ValidateConsultationRefs(refs); err != nil {
			return fmt.Errorf("agent_consultations[%d]: %w", i, err)
		}
	}
	for i, pol := range s.PolicyEvaluations {
		if err := pol.ValidatePolicyEvaluationRefs(refs); err != nil {
			return fmt.Errorf("policy_evaluations[%d]: %w", i, err)
		}
	}
	for i, appr := range s.RepairApprovals {
		if err := appr.ValidateRepairApprovalRefs(refs); err != nil {
			return fmt.Errorf("repair_approvals[%d]: %w", i, err)
		}
	}
	if s.WorkflowState == nil {
		if len(s.EvidenceAcquisitions) > 0 || len(s.AgentConsultations) > 0 ||
			len(s.PolicyEvaluations) > 0 || len(s.RepairApprovals) > 0 {
			return fmt.Errorf("%w: evidence acquisitions, consultations, policy, and approvals require workflow_state", ErrInvalidArgument)
		}
	} else {
		if err := s.WorkflowState.ValidateWorkflowRefs(refs); err != nil {
			return fmt.Errorf("workflow_state: %w", err)
		}
		if s.WorkflowState.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: workflow_state.case_id mismatch", ErrInvalidArgument)
		}
		if !domain.CompatibleWorkflowAndCaseState(s.WorkflowState.State, s.Case.CurrentState) {
			return fmt.Errorf("%w: workflow state %q incompatible with case current_state %q",
				ErrInvalidArgument, s.WorkflowState.State, s.Case.CurrentState)
		}
		if err := validateWorkflowTransitionIntegrity(s); err != nil {
			return err
		}
		if err := validateEvidenceAcquisitionOrigin(s); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
		}
	}
	return nil
}

// validateWorkflowTransitionIntegrity enforces the PR #17 revision model:
// each state-changing coordinator-event carries an explicit workflow_revision;
// revisions are unique and form the contiguous sequence 1..WorkflowState.Revision;
// last_transition_id must reference the event with the maximum revision.
// Ordering does not depend on occurred_at or event_id.
func validateWorkflowTransitionIntegrity(s Snapshot) error {
	ws := s.WorkflowState
	byID := make(map[string]domain.CoordinatorEvent, len(s.CoordinatorEvents))
	byRev := make(map[uint64]domain.CoordinatorEvent)
	var changing []domain.CoordinatorEvent
	for _, ev := range s.CoordinatorEvents {
		byID[ev.EventID] = ev
		isChanging := domain.IsStateChangingCoordinatorEventType(ev.EventType)
		if !isChanging {
			if ev.WorkflowRevision != 0 {
				return fmt.Errorf("%w: non-state-changing event %q must not set workflow_revision",
					ErrInvalidArgument, ev.EventID)
			}
			continue
		}
		if ev.WorkflowRevision == 0 {
			return fmt.Errorf("%w: state-changing event %q requires workflow_revision >= 1",
				ErrInvalidArgument, ev.EventID)
		}
		if _, dup := byRev[ev.WorkflowRevision]; dup {
			return fmt.Errorf("%w: duplicate workflow_revision %d", ErrInvalidArgument, ev.WorkflowRevision)
		}
		byRev[ev.WorkflowRevision] = ev
		changing = append(changing, ev)
		if err := domain.ValidatePR17CoordinatorEventSemantics(ev); err != nil {
			return err
		}
	}
	if uint64(len(changing)) != ws.Revision {
		return fmt.Errorf("%w: workflow revision %d != state-changing event count %d",
			ErrInvalidArgument, ws.Revision, len(changing))
	}
	if ws.Revision == 0 {
		return fmt.Errorf("%w: workflow present with revision 0", ErrInvalidArgument)
	}
	for rev := uint64(1); rev <= ws.Revision; rev++ {
		if _, ok := byRev[rev]; !ok {
			return fmt.Errorf("%w: missing workflow_revision %d in contiguous sequence 1..%d",
				ErrInvalidArgument, rev, ws.Revision)
		}
	}
	for rev := uint64(2); rev <= ws.Revision; rev++ {
		prev := byRev[rev-1]
		curr := byRev[rev]
		prevAt, err := time.Parse(time.RFC3339, prev.OccurredAt)
		if err != nil {
			return fmt.Errorf("%w: workflow revision %d occurred_at: %v", ErrInvalidArgument, rev-1, err)
		}
		currAt, err := time.Parse(time.RFC3339, curr.OccurredAt)
		if err != nil {
			return fmt.Errorf("%w: workflow revision %d occurred_at: %v", ErrInvalidArgument, rev, err)
		}
		if currAt.Before(prevAt) {
			return fmt.Errorf("%w: workflow revision %d occurred_at %q precedes revision %d occurred_at %q",
				ErrInvalidArgument, rev, curr.OccurredAt, rev-1, prev.OccurredAt)
		}
	}
	last, ok := byID[ws.LastTransitionID]
	if !ok {
		return fmt.Errorf("%w: last_transition_id %q missing", ErrInvalidArgument, ws.LastTransitionID)
	}
	if last.CaseID != s.Case.CaseID {
		return fmt.Errorf("%w: last transition event case_id mismatch", ErrInvalidArgument)
	}
	if last.NextState != string(ws.State) {
		return fmt.Errorf("%w: last transition next_state %q != workflow state %q",
			ErrInvalidArgument, last.NextState, ws.State)
	}
	if !domain.IsStateChangingCoordinatorEventType(last.EventType) {
		return fmt.Errorf("%w: last_transition_id event type %q is not state-changing",
			ErrInvalidArgument, last.EventType)
	}
	first := byRev[1]
	if first.EventType != domain.EventCaseCreated && first.EventType != domain.EventLegacyCaseAdopted {
		return fmt.Errorf("%w: workflow revision 1 must be case_created or legacy_case_adopted", ErrInvalidArgument)
	}
	for rev := uint64(2); rev <= ws.Revision; rev++ {
		prev := byRev[rev-1]
		curr := byRev[rev]
		if curr.PreviousState != prev.NextState {
			return fmt.Errorf("%w: workflow revision %d previous_state %q does not continue revision %d next_state %q",
				ErrInvalidArgument, rev, curr.PreviousState, rev-1, prev.NextState)
		}
	}
	maxEv := byRev[ws.Revision]
	if last.EventID != maxEv.EventID || last.WorkflowRevision != ws.Revision {
		return fmt.Errorf("%w: last_transition_id %q is not the max workflow_revision event %q (revision %d)",
			ErrInvalidArgument, ws.LastTransitionID, maxEv.EventID, ws.Revision)
	}
	if maxEv.NextState != string(ws.State) {
		return fmt.Errorf("%w: max workflow_revision next_state %q != workflow state %q",
			ErrInvalidArgument, maxEv.NextState, ws.State)
	}
	if err := domain.ValidatePR17WorkflowStateSemantics(*ws, s.Case, maxEv); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := validateLifecycleProvenance(s); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return nil
}

func validateLifecycleProvenance(s Snapshot) error {
	if len(s.ExecutionEvents) > 0 {
		return fmt.Errorf("execution events are not implemented in PR #17")
	}
	if len(s.VerificationReports) > 0 {
		return fmt.Errorf("verification reports are not implemented in PR #17")
	}
	if s.WorkflowState == nil {
		return nil
	}

	auditedFindings := make(map[string]struct{})
	auditedPlans := make(map[string]struct{})
	auditedAllowedPolicy := make(map[string]struct{})
	auditedApprovals := make(map[string]struct{})
	for _, ev := range s.CoordinatorEvents {
		switch ev.EventType {
		case domain.EventAnalysisCommitted:
			for _, id := range ev.ReferencedDocumentIDs {
				if findFindingByID(s.Findings, id) != nil {
					auditedFindings[id] = struct{}{}
				}
			}
		case domain.EventPlanCommitted:
			for _, id := range ev.ReferencedDocumentIDs {
				if findPlanByID(s.RepairPlans, id) != nil {
					auditedPlans[id] = struct{}{}
				}
			}
		case domain.EventPolicyEvaluated:
			for _, id := range ev.ReferencedDocumentIDs {
				if findPolicyEvaluationByID(s.PolicyEvaluations, id) != nil {
					auditedAllowedPolicy[id] = struct{}{}
				}
			}
		case domain.EventApprovalCommitted:
			for _, id := range ev.ReferencedDocumentIDs {
				if findRepairApprovalByID(s.RepairApprovals, id) != nil {
					auditedApprovals[id] = struct{}{}
				}
			}
		}
	}
	for _, f := range s.Findings {
		if _, ok := auditedFindings[f.FindingID]; !ok {
			return fmt.Errorf("finding %q lacks analysis_committed provenance", f.FindingID)
		}
	}
	for _, p := range s.RepairPlans {
		if _, ok := auditedPlans[p.PlanID]; !ok {
			return fmt.Errorf("plan %q lacks plan_committed provenance", p.PlanID)
		}
	}
	for _, pol := range s.PolicyEvaluations {
		if pol.Decision == "allowed" {
			if _, ok := auditedAllowedPolicy[pol.EvaluationID]; !ok {
				return fmt.Errorf("policy evaluation %q lacks policy_evaluated provenance", pol.EvaluationID)
			}
		}
	}
	for _, appr := range s.RepairApprovals {
		if _, ok := auditedApprovals[appr.ApprovalID]; !ok {
			return fmt.Errorf("repair approval %q lacks approval_committed provenance", appr.ApprovalID)
		}
	}

	switch s.WorkflowState.State {
	case domain.WorkflowEvidenceCollected:
		if len(s.Findings) > 0 || len(s.RepairPlans) > 0 {
			return fmt.Errorf("state %q must not contain findings or repair plans", s.WorkflowState.State)
		}
	case domain.WorkflowAnalyzed:
		if len(s.Findings) == 0 {
			return fmt.Errorf("state %q requires at least one finding", s.WorkflowState.State)
		}
		if len(s.RepairPlans) > 0 {
			return fmt.Errorf("state %q must not contain repair plans", s.WorkflowState.State)
		}
	case domain.WorkflowPlanProposed, domain.WorkflowAwaitingApproval, domain.WorkflowApproved:
		if len(s.Findings) == 0 {
			return fmt.Errorf("state %q requires audited findings", s.WorkflowState.State)
		}
		if len(s.RepairPlans) == 0 {
			return fmt.Errorf("state %q requires audited repair plans", s.WorkflowState.State)
		}
		if s.WorkflowState.ActivePlanID == "" {
			return fmt.Errorf("state %q requires active_plan_id", s.WorkflowState.State)
		}
		if findPlanByID(s.RepairPlans, s.WorkflowState.ActivePlanID) == nil {
			return fmt.Errorf("active_plan_id %q missing from repair plans", s.WorkflowState.ActivePlanID)
		}
		if s.WorkflowState.State == domain.WorkflowAwaitingApproval && len(s.PolicyEvaluations) == 0 {
			return fmt.Errorf("state %q requires at least one policy evaluation", s.WorkflowState.State)
		}
		if s.WorkflowState.State == domain.WorkflowApproved {
			if len(s.RepairApprovals) == 0 {
				return fmt.Errorf("state %q requires at least one repair approval", s.WorkflowState.State)
			}
			hasAllowed := false
			for _, pol := range s.PolicyEvaluations {
				if pol.Decision == "allowed" {
					hasAllowed = true
					break
				}
			}
			if !hasAllowed {
				return fmt.Errorf("state %q requires an allowed policy evaluation", s.WorkflowState.State)
			}
		}
	case domain.WorkflowFailed, domain.WorkflowCancelled:
		// Existing findings/plans already require provenance above.
	}
	return nil
}

func validateCoordinatorEventReferenceSemantics(s Snapshot, ev domain.CoordinatorEvent) error {
	if containsRef(ev.ReferencedDocumentIDs, ev.EventID) {
		return fmt.Errorf("referenced_document_ids must not self-reference event_id")
	}
	for _, id := range ev.ReferencedDocumentIDs {
		if strings.HasPrefix(id, "cevt-") {
			return fmt.Errorf("referenced_document_ids must not contain coordinator event ids")
		}
	}
	if !containsRef(ev.ReferencedDocumentIDs, s.Case.CaseID) {
		return fmt.Errorf("referenced_document_ids must contain case id")
	}
	if !containsRef(ev.ReferencedDocumentIDs, domain.DocumentIDCaseWorkflowState) {
		return fmt.Errorf("referenced_document_ids must contain case-workflow-state")
	}
	switch ev.EventType {
	case domain.EventCaseCreated, domain.EventLegacyCaseAdopted:
		want := createOrAdoptReferenceSet(s)
		if err := requireExactRefSet(ev.ReferencedDocumentIDs, want); err != nil {
			return fmt.Errorf("%s refs: %w", ev.EventType, err)
		}
	case domain.EventAnalysisCommitted:
		want, err := analysisReferenceClosure(s, ev)
		if err != nil {
			return err
		}
		if err := requireExactRefSet(ev.ReferencedDocumentIDs, want); err != nil {
			return fmt.Errorf("analysis refs: %w", err)
		}
	case domain.EventPlanCommitted:
		want, err := planReferenceClosure(s, ev)
		if err != nil {
			return err
		}
		if err := requireExactRefSet(ev.ReferencedDocumentIDs, want); err != nil {
			return fmt.Errorf("plan refs: %w", err)
		}
	case domain.EventPolicyEvaluated:
		want, err := policyReferenceClosure(s, ev)
		if err != nil {
			return err
		}
		if err := requireExactRefSet(ev.ReferencedDocumentIDs, want); err != nil {
			return fmt.Errorf("policy refs: %w", err)
		}
	case domain.EventApprovalCommitted:
		want, err := approvalReferenceClosure(s, ev)
		if err != nil {
			return err
		}
		if err := requireExactRefSet(ev.ReferencedDocumentIDs, want); err != nil {
			return fmt.Errorf("approval refs: %w", err)
		}
	case domain.EventCaseFailed, domain.EventCaseCancelled:
		want := []string{s.Case.CaseID, domain.DocumentIDCaseWorkflowState}
		if s.WorkflowState != nil && s.WorkflowState.ActivePlanID != "" {
			want = append(want, s.WorkflowState.ActivePlanID)
		}
		if err := requireExactRefSet(ev.ReferencedDocumentIDs, want); err != nil {
			return fmt.Errorf("terminal refs: %w", err)
		}
	}
	return nil
}

func createOrAdoptReferenceSet(s Snapshot) []string {
	initialTargets, initialEvidence := initialTargetAndEvidenceIDs(s)
	want := []string{s.Case.CaseID, domain.DocumentIDCaseWorkflowState}
	want = append(want, initialTargets...)
	want = append(want, initialEvidence...)
	return uniqueSortedStrings(want)
}

func initialTargetAndEvidenceIDs(s Snapshot) (targets []string, evidence []string) {
	addedTargets := make(map[string]struct{})
	addedEvidence := make(map[string]struct{})
	for _, acq := range s.EvidenceAcquisitions {
		for _, id := range acq.AddedTargetIDs {
			addedTargets[id] = struct{}{}
		}
		for _, id := range acq.AddedEvidenceIDs {
			addedEvidence[id] = struct{}{}
		}
	}
	for _, t := range s.Targets {
		if _, ok := addedTargets[t.TargetID]; !ok {
			targets = append(targets, t.TargetID)
		}
	}
	for _, e := range s.EvidenceBundles {
		if _, ok := addedEvidence[e.EvidenceID]; !ok {
			evidence = append(evidence, e.EvidenceID)
		}
	}
	return targets, evidence
}

func validateEvidenceAcquisitionOrigin(s Snapshot) error {
	addedTargets := make(map[string]string) // id -> acquisition_id
	addedEvidence := make(map[string]string)
	for _, acq := range s.EvidenceAcquisitions {
		for _, id := range acq.TargetIDs {
			if findTargetByID(s.Targets, id) == nil {
				return fmt.Errorf("acquisition %q target_ids contains unknown %q", acq.AcquisitionID, id)
			}
		}
		for _, id := range acq.InputEvidenceIDs {
			if findEvidenceByID(s.EvidenceBundles, id) == nil {
				return fmt.Errorf("acquisition %q input_evidence_ids contains unknown %q", acq.AcquisitionID, id)
			}
		}
		for _, id := range acq.AddedTargetIDs {
			if findTargetByID(s.Targets, id) == nil {
				return fmt.Errorf("acquisition %q added_target_ids contains missing %q", acq.AcquisitionID, id)
			}
			if prev, ok := addedTargets[id]; ok {
				return fmt.Errorf("target %q claimed by acquisitions %q and %q", id, prev, acq.AcquisitionID)
			}
			addedTargets[id] = acq.AcquisitionID
		}
		for _, id := range acq.AddedEvidenceIDs {
			if findEvidenceByID(s.EvidenceBundles, id) == nil {
				return fmt.Errorf("acquisition %q added_evidence_ids contains missing %q", acq.AcquisitionID, id)
			}
			if prev, ok := addedEvidence[id]; ok {
				return fmt.Errorf("evidence %q claimed by acquisitions %q and %q", id, prev, acq.AcquisitionID)
			}
			addedEvidence[id] = acq.AcquisitionID
		}
	}

	initialTargets, initialEvidence := initialTargetAndEvidenceIDs(s)
	initialTargetSet := setOf(initialTargets...)
	initialEvidenceSet := setOf(initialEvidence...)

	for id := range addedTargets {
		if _, ok := initialTargetSet[id]; ok {
			return fmt.Errorf("target %q cannot be both initial and acquired", id)
		}
	}
	for id := range addedEvidence {
		if _, ok := initialEvidenceSet[id]; ok {
			return fmt.Errorf("evidence %q cannot be both initial and acquired", id)
		}
	}

	for _, t := range s.Targets {
		_, initial := initialTargetSet[t.TargetID]
		_, added := addedTargets[t.TargetID]
		if initial == added {
			return fmt.Errorf("target %q lacks exactly one origin", t.TargetID)
		}
	}
	for _, e := range s.EvidenceBundles {
		_, initial := initialEvidenceSet[e.EvidenceID]
		_, added := addedEvidence[e.EvidenceID]
		if initial == added {
			return fmt.Errorf("evidence %q lacks exactly one origin", e.EvidenceID)
		}
	}

	if len(s.EvidenceAcquisitions) == 0 {
		return nil
	}
	// When acquisitions exist, revision-1 event must cover only initial IDs
	// (already enforced by createOrAdoptReferenceSet exact match).
	return nil
}

func analysisReferenceClosure(s Snapshot, ev domain.CoordinatorEvent) ([]string, error) {
	want := []string{s.Case.CaseID, domain.DocumentIDCaseWorkflowState}
	found := 0
	for _, id := range ev.ReferencedDocumentIDs {
		if findFindingByID(s.Findings, id) == nil {
			continue
		}
		finding := findFindingByID(s.Findings, id)
		found++
		want = append(want, finding.FindingID)
		want = append(want, finding.EvidenceRefs...)
		want = append(want, finding.AffectedTargetIDs...)
	}
	if found == 0 {
		return nil, fmt.Errorf("analysis_committed requires at least one finding ref")
	}
	return uniqueSortedStrings(want), nil
}

func planReferenceClosure(s Snapshot, ev domain.CoordinatorEvent) ([]string, error) {
	want := []string{s.Case.CaseID, domain.DocumentIDCaseWorkflowState}
	var plans []domain.RepairPlan
	for _, id := range ev.ReferencedDocumentIDs {
		if plan := findPlanByID(s.RepairPlans, id); plan != nil {
			plans = append(plans, *plan)
		}
	}
	if len(plans) != 1 {
		return nil, fmt.Errorf("plan_committed requires exactly one plan ref")
	}
	plan := plans[0]
	if s.WorkflowState != nil && s.WorkflowState.State == domain.WorkflowPlanProposed &&
		s.WorkflowState.ActivePlanID != plan.PlanID {
		return nil, fmt.Errorf("plan_committed active_plan_id must match referenced plan")
	}
	want = append(want, plan.PlanID)
	want = append(want, plan.FindingRefs...)
	for _, step := range plan.Steps {
		want = append(want, step.TargetID)
	}
	return uniqueSortedStrings(want), nil
}

func policyReferenceClosure(s Snapshot, ev domain.CoordinatorEvent) ([]string, error) {
	if s.WorkflowState == nil || s.WorkflowState.ActivePlanID == "" {
		return nil, fmt.Errorf("policy_evaluated requires active_plan_id")
	}
	plan := findPlanByID(s.RepairPlans, s.WorkflowState.ActivePlanID)
	if plan == nil {
		return nil, fmt.Errorf("policy_evaluated active plan missing")
	}
	var evals []domain.PolicyEvaluation
	for _, id := range ev.ReferencedDocumentIDs {
		if pol := findPolicyEvaluationByID(s.PolicyEvaluations, id); pol != nil {
			evals = append(evals, *pol)
		}
	}
	if len(evals) != 1 {
		return nil, fmt.Errorf("policy_evaluated requires exactly one evaluation ref")
	}
	eval := evals[0]
	if eval.Decision != "allowed" {
		return nil, fmt.Errorf("policy_evaluated requires allowed decision")
	}
	if eval.PlanID != plan.PlanID {
		return nil, fmt.Errorf("policy_evaluated plan_id mismatch")
	}
	want := []string{s.Case.CaseID, domain.DocumentIDCaseWorkflowState, plan.PlanID, eval.EvaluationID}
	want = append(want, plan.FindingRefs...)
	for _, step := range plan.Steps {
		want = append(want, step.TargetID)
	}
	return uniqueSortedStrings(want), nil
}

func approvalReferenceClosure(s Snapshot, ev domain.CoordinatorEvent) ([]string, error) {
	if s.WorkflowState == nil || s.WorkflowState.ActivePlanID == "" {
		return nil, fmt.Errorf("approval_committed requires active_plan_id")
	}
	plan := findPlanByID(s.RepairPlans, s.WorkflowState.ActivePlanID)
	if plan == nil {
		return nil, fmt.Errorf("approval_committed active plan missing")
	}
	var evals []domain.PolicyEvaluation
	var approvals []domain.RepairApproval
	for _, id := range ev.ReferencedDocumentIDs {
		if pol := findPolicyEvaluationByID(s.PolicyEvaluations, id); pol != nil {
			evals = append(evals, *pol)
		}
		if appr := findRepairApprovalByID(s.RepairApprovals, id); appr != nil {
			approvals = append(approvals, *appr)
		}
	}
	if len(approvals) != 1 {
		return nil, fmt.Errorf("approval_committed requires exactly one approval ref")
	}
	if len(evals) != 1 {
		return nil, fmt.Errorf("approval_committed requires exactly one evaluation ref")
	}
	approval := approvals[0]
	eval := evals[0]
	if eval.Decision != "allowed" {
		return nil, fmt.Errorf("approval_committed requires allowed policy evaluation")
	}
	if approval.PlanID != plan.PlanID || eval.PlanID != plan.PlanID {
		return nil, fmt.Errorf("approval_committed plan_id mismatch")
	}
	want := []string{s.Case.CaseID, domain.DocumentIDCaseWorkflowState, plan.PlanID, eval.EvaluationID, approval.ApprovalID}
	want = append(want, plan.FindingRefs...)
	for _, step := range plan.Steps {
		want = append(want, step.TargetID)
	}
	return uniqueSortedStrings(want), nil
}

func requireExactRefSet(got []string, want []string) error {
	gotSet := uniqueSortedStrings(got)
	wantSet := uniqueSortedStrings(want)
	if len(gotSet) != len(wantSet) {
		return fmt.Errorf("exact ref set mismatch: got %v want %v", gotSet, wantSet)
	}
	for i := range gotSet {
		if gotSet[i] != wantSet[i] {
			return fmt.Errorf("exact ref set mismatch: got %v want %v", gotSet, wantSet)
		}
	}
	return nil
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func containsRef(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func findFindingByID(values []domain.Finding, want string) *domain.Finding {
	for i := range values {
		if values[i].FindingID == want {
			return &values[i]
		}
	}
	return nil
}

func findPlanByID(values []domain.RepairPlan, want string) *domain.RepairPlan {
	for i := range values {
		if values[i].PlanID == want {
			return &values[i]
		}
	}
	return nil
}

func findTargetByID(values []domain.Target, want string) *domain.Target {
	for i := range values {
		if values[i].TargetID == want {
			return &values[i]
		}
	}
	return nil
}

func findEvidenceByID(values []domain.EvidenceBundle, want string) *domain.EvidenceBundle {
	for i := range values {
		if values[i].EvidenceID == want {
			return &values[i]
		}
	}
	return nil
}

func findPolicyEvaluationByID(values []domain.PolicyEvaluation, want string) *domain.PolicyEvaluation {
	for i := range values {
		if values[i].EvaluationID == want {
			return &values[i]
		}
	}
	return nil
}

func findRepairApprovalByID(values []domain.RepairApproval, want string) *domain.RepairApproval {
	for i := range values {
		if values[i].ApprovalID == want {
			return &values[i]
		}
	}
	return nil
}

func setOf(ids ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func artifactIDSet(m map[string]domain.ArtifactRef) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for id := range m {
		out[id] = struct{}{}
	}
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
		Case:                 result.Case,
		Targets:              append([]domain.Target(nil), result.Targets...),
		EvidenceBundles:      append([]domain.EvidenceBundle(nil), result.EvidenceBundles...),
		Findings:             []domain.Finding{},
		RepairPlans:          []domain.RepairPlan{},
		ExecutionEvents:      []domain.ExecutionEvent{},
		VerificationReports:  []domain.VerificationReport{},
		CoordinatorEvents:    []domain.CoordinatorEvent{},
		EvidenceAcquisitions: []domain.EvidenceAcquisitionRecord{},
		AgentConsultations:   []domain.AgentConsultation{},
		PolicyEvaluations:    []domain.PolicyEvaluation{},
		RepairApprovals:      []domain.RepairApproval{},
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
	snap.Normalize()
	var docs []preparedDocument

	caseBytes, err := marshalCanonical(snap.Case)
	if err != nil {
		return nil, fmt.Errorf("marshal case-manifest: %w", err)
	}
	docs = append(docs, documentEntry("case-manifest.json", caseBytes))

	if snap.WorkflowState != nil {
		raw, err := marshalCanonical(snap.WorkflowState)
		if err != nil {
			return nil, fmt.Errorf("marshal case-workflow-state: %w", err)
		}
		docs = append(docs, documentEntry("case-workflow-state.json", raw))
	}

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

	findings := append([]domain.Finding(nil), snap.Findings...)
	sort.Slice(findings, func(i, j int) bool { return findings[i].FindingID < findings[j].FindingID })
	for _, f := range findings {
		if err := validateFindingID(f.FindingID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(f)
		if err != nil {
			return nil, fmt.Errorf("marshal finding %s: %w", f.FindingID, err)
		}
		docs = append(docs, documentEntry("findings/"+f.FindingID+".json", raw))
	}

	plans := append([]domain.RepairPlan(nil), snap.RepairPlans...)
	sort.Slice(plans, func(i, j int) bool { return plans[i].PlanID < plans[j].PlanID })
	for _, p := range plans {
		if err := validatePlanID(p.PlanID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(p)
		if err != nil {
			return nil, fmt.Errorf("marshal plan %s: %w", p.PlanID, err)
		}
		docs = append(docs, documentEntry("plans/"+p.PlanID+".json", raw))
	}

	execs := append([]domain.ExecutionEvent(nil), snap.ExecutionEvents...)
	sort.Slice(execs, func(i, j int) bool { return execs[i].ExecutionID < execs[j].ExecutionID })
	for _, e := range execs {
		if err := validateExecutionID(e.ExecutionID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(e)
		if err != nil {
			return nil, fmt.Errorf("marshal execution %s: %w", e.ExecutionID, err)
		}
		docs = append(docs, documentEntry("executions/"+e.ExecutionID+".json", raw))
	}

	verifs := append([]domain.VerificationReport(nil), snap.VerificationReports...)
	sort.Slice(verifs, func(i, j int) bool { return verifs[i].VerificationID < verifs[j].VerificationID })
	for _, v := range verifs {
		if err := validateVerificationID(v.VerificationID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(v)
		if err != nil {
			return nil, fmt.Errorf("marshal verification %s: %w", v.VerificationID, err)
		}
		docs = append(docs, documentEntry("verifications/"+v.VerificationID+".json", raw))
	}

	events := append([]domain.CoordinatorEvent(nil), snap.CoordinatorEvents...)
	sort.Slice(events, func(i, j int) bool { return events[i].EventID < events[j].EventID })
	for _, ev := range events {
		if err := validateCoordinatorEventID(ev.EventID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(ev)
		if err != nil {
			return nil, fmt.Errorf("marshal coordinator-event %s: %w", ev.EventID, err)
		}
		docs = append(docs, documentEntry("coordinator-events/"+ev.EventID+".json", raw))
	}

	acqs := append([]domain.EvidenceAcquisitionRecord(nil), snap.EvidenceAcquisitions...)
	sort.Slice(acqs, func(i, j int) bool { return acqs[i].AcquisitionID < acqs[j].AcquisitionID })
	for _, acq := range acqs {
		if err := validateAcquisitionID(acq.AcquisitionID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(acq)
		if err != nil {
			return nil, fmt.Errorf("marshal evidence-acquisition %s: %w", acq.AcquisitionID, err)
		}
		docs = append(docs, documentEntry("evidence-acquisitions/"+acq.AcquisitionID+".json", raw))
	}

	consultations := append([]domain.AgentConsultation(nil), snap.AgentConsultations...)
	sort.Slice(consultations, func(i, j int) bool {
		return consultations[i].ConsultationID < consultations[j].ConsultationID
	})
	for _, cons := range consultations {
		if err := validateConsultationID(cons.ConsultationID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(cons)
		if err != nil {
			return nil, fmt.Errorf("marshal agent-consultation %s: %w", cons.ConsultationID, err)
		}
		docs = append(docs, documentEntry("agent-consultations/"+cons.ConsultationID+".json", raw))
	}

	policies := append([]domain.PolicyEvaluation(nil), snap.PolicyEvaluations...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].EvaluationID < policies[j].EvaluationID })
	for _, pol := range policies {
		if err := validatePolicyEvaluationID(pol.EvaluationID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(pol)
		if err != nil {
			return nil, fmt.Errorf("marshal policy-evaluation %s: %w", pol.EvaluationID, err)
		}
		docs = append(docs, documentEntry("policy-evaluations/"+pol.EvaluationID+".json", raw))
	}

	approvals := append([]domain.RepairApproval(nil), snap.RepairApprovals...)
	sort.Slice(approvals, func(i, j int) bool { return approvals[i].ApprovalID < approvals[j].ApprovalID })
	for _, appr := range approvals {
		if err := validateRepairApprovalID(appr.ApprovalID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(appr)
		if err != nil {
			return nil, fmt.Errorf("marshal repair-approval %s: %w", appr.ApprovalID, err)
		}
		docs = append(docs, documentEntry("repair-approvals/"+appr.ApprovalID+".json", raw))
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
