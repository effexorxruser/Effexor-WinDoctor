package domain

import "fmt"

// CrossRefs holds IDs that documents may reference.
type CrossRefs struct {
	CaseIDs             map[string]struct{}
	TargetIDs           map[string]struct{}
	EvidenceIDs         map[string]struct{}
	FindingIDs          map[string]struct{}
	PlanIDs             map[string]struct{}
	ExecutionIDs        map[string]struct{}
	VerificationIDs     map[string]struct{}
	ArtifactIDs         map[string]struct{}
	CoordinatorEventIDs map[string]struct{}
	// DocumentIDs is the full set of referencable document identifiers,
	// including singleton typed IDs such as DocumentIDCaseWorkflowState.
	DocumentIDs map[string]struct{}
}

func setOf(ids ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func requireRef(kind, id string, known map[string]struct{}) error {
	if _, ok := known[id]; !ok {
		return fmt.Errorf("%s %q is not present in known set", kind, id)
	}
	return nil
}

// ValidateFindingRefs checks finding evidence/target refs against known IDs.
func (f Finding) ValidateFindingRefs(refs CrossRefs) error {
	if err := f.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", f.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	for _, id := range f.EvidenceRefs {
		if err := requireRef("evidence_ref", id, refs.EvidenceIDs); err != nil {
			return err
		}
	}
	for _, id := range f.AffectedTargetIDs {
		if err := requireRef("affected_target_id", id, refs.TargetIDs); err != nil {
			return err
		}
	}
	return nil
}

// ValidatePlanRefs checks plan finding and target refs.
func (p RepairPlan) ValidatePlanRefs(refs CrossRefs) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", p.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	for _, id := range p.FindingRefs {
		if err := requireRef("finding_ref", id, refs.FindingIDs); err != nil {
			return err
		}
	}
	for _, step := range p.Steps {
		if err := requireRef("step.target_id", step.TargetID, refs.TargetIDs); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEvidenceRefs checks evidence case/target refs.
func (e EvidenceBundle) ValidateEvidenceRefs(refs CrossRefs) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", e.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	if err := requireRef("target_id", e.TargetID, refs.TargetIDs); err != nil {
		return err
	}
	return nil
}

// ValidateExecutionRefs checks execution case/target/artifact refs.
func (e ExecutionEvent) ValidateExecutionRefs(refs CrossRefs) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", e.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	if err := requireRef("target_id", e.TargetID, refs.TargetIDs); err != nil {
		return err
	}
	if e.StdoutArtifact != "" {
		if err := requireRef("stdout_artifact", e.StdoutArtifact, refs.ArtifactIDs); err != nil {
			return err
		}
	}
	if e.StderrArtifact != "" {
		if err := requireRef("stderr_artifact", e.StderrArtifact, refs.ArtifactIDs); err != nil {
			return err
		}
	}
	return nil
}

// ValidateVerificationRefs checks verification case/execution/evidence refs.
func (v VerificationReport) ValidateVerificationRefs(refs CrossRefs) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", v.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	if err := requireRef("execution_id", v.ExecutionID, refs.ExecutionIDs); err != nil {
		return err
	}
	for _, id := range v.EvidenceRefs {
		if err := requireRef("evidence_ref", id, refs.EvidenceIDs); err != nil {
			return err
		}
	}
	return nil
}

// ValidateWorkflowRefs checks workflow case/plan/execution/transition refs.
func (w CaseWorkflowState) ValidateWorkflowRefs(refs CrossRefs) error {
	if err := w.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", w.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	if w.ActivePlanID != "" {
		if err := requireRef("active_plan_id", w.ActivePlanID, refs.PlanIDs); err != nil {
			return err
		}
	}
	if w.ActiveExecutionID != "" {
		if err := requireRef("active_execution_id", w.ActiveExecutionID, refs.ExecutionIDs); err != nil {
			return err
		}
	}
	if err := requireRef("last_transition_id", w.LastTransitionID, refs.CoordinatorEventIDs); err != nil {
		return err
	}
	return nil
}

// ValidateCoordinatorEventRefs checks coordinator event case_id and document refs.
func (e CoordinatorEvent) ValidateCoordinatorEventRefs(refs CrossRefs) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", e.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(e.ReferencedDocumentIDs))
	for i, id := range e.ReferencedDocumentIDs {
		if id == "" {
			return fmt.Errorf("referenced_document_ids[%d] must not be empty", i)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("referenced_document_ids contains duplicate %q", id)
		}
		seen[id] = struct{}{}
		if err := requireRef(fmt.Sprintf("referenced_document_ids[%d]", i), id, refs.DocumentIDs); err != nil {
			return err
		}
	}
	return nil
}

// NewCrossRefs is a convenience constructor for tests and importers.
func NewCrossRefs(caseIDs, targetIDs, evidenceIDs, findingIDs, executionIDs, artifactIDs []string) CrossRefs {
	return CrossRefs{
		CaseIDs:      setOf(caseIDs...),
		TargetIDs:    setOf(targetIDs...),
		EvidenceIDs:  setOf(evidenceIDs...),
		FindingIDs:   setOf(findingIDs...),
		ExecutionIDs: setOf(executionIDs...),
		ArtifactIDs:  setOf(artifactIDs...),
	}
}
