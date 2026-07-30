package coordinator

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func uniqueRefs(ids ...string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func createOrAdoptRefs(snap casestore.Snapshot) []string {
	refs := make([]string, 0, 2+len(snap.Targets)+len(snap.EvidenceBundles))
	refs = append(refs, snap.Case.CaseID)
	for _, t := range snap.Targets {
		refs = append(refs, t.TargetID)
	}
	for _, e := range snap.EvidenceBundles {
		refs = append(refs, e.EvidenceID)
	}
	refs = append(refs, domain.DocumentIDCaseWorkflowState)
	return uniqueRefs(refs...)
}

func analysisRefs(caseID string, findings []domain.Finding) []string {
	refs := []string{caseID}
	for _, f := range findings {
		refs = append(refs, f.FindingID)
		refs = append(refs, f.EvidenceRefs...)
		refs = append(refs, f.AffectedTargetIDs...)
	}
	refs = append(refs, domain.DocumentIDCaseWorkflowState)
	return uniqueRefs(refs...)
}

func planRefs(caseID string, plan domain.RepairPlan) []string {
	refs := []string{caseID, plan.PlanID}
	refs = append(refs, plan.FindingRefs...)
	for _, step := range plan.Steps {
		refs = append(refs, step.TargetID)
	}
	refs = append(refs, domain.DocumentIDCaseWorkflowState)
	return uniqueRefs(refs...)
}

func terminalRefs(snap casestore.Snapshot) []string {
	refs := []string{snap.Case.CaseID, domain.DocumentIDCaseWorkflowState}
	if snap.WorkflowState != nil && snap.WorkflowState.ActivePlanID != "" {
		refs = append(refs, snap.WorkflowState.ActivePlanID)
	}
	return uniqueRefs(refs...)
}
