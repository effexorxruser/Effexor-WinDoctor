package domain

import "fmt"

// Finding is an interpreted conclusion grounded in evidence.
type Finding struct {
	SchemaName           string   `json:"schema_name"`
	SchemaVersion        string   `json:"schema_version"`
	FindingID            string   `json:"finding_id"`
	CaseID               string   `json:"case_id"`
	Severity             string   `json:"severity"`
	Confidence           string   `json:"confidence"`
	Title                string   `json:"title"`
	Rationale            string   `json:"rationale"`
	EvidenceRefs         []string `json:"evidence_refs"`
	AffectedTargetIDs    []string `json:"affected_target_ids"`
	RecommendedWorkflows []string `json:"recommended_workflows"`
	Limitations          []string `json:"limitations"`
	InsufficientEvidence bool     `json:"insufficient_evidence,omitempty"`
}

var severities = map[string]struct{}{
	"info":     {},
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

var confidences = map[string]struct{}{
	"low":    {},
	"medium": {},
	"high":   {},
}

func (f Finding) Validate() error {
	if err := requireSchema(f.SchemaName, f.SchemaVersion, SchemaFinding); err != nil {
		return err
	}
	if err := requireMatch("finding_id", f.FindingID, reFindingID); err != nil {
		return err
	}
	if err := requireMatch("case_id", f.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireEnum("severity", f.Severity, severities); err != nil {
		return err
	}
	if err := requireEnum("confidence", f.Confidence, confidences); err != nil {
		return err
	}
	if err := requireNonEmpty("title", f.Title); err != nil {
		return err
	}
	if err := requireNonEmpty("rationale", f.Rationale); err != nil {
		return err
	}
	if f.EvidenceRefs == nil {
		return fmt.Errorf("evidence_refs is required")
	}
	if len(f.EvidenceRefs) == 0 && !f.InsufficientEvidence {
		return fmt.Errorf("finding without evidence_refs must set insufficient_evidence=true")
	}
	for i, id := range f.EvidenceRefs {
		if err := requireMatch(fmt.Sprintf("evidence_refs[%d]", i), id, reEvidenceID); err != nil {
			return err
		}
	}
	if f.AffectedTargetIDs == nil {
		return fmt.Errorf("affected_target_ids is required")
	}
	for i, id := range f.AffectedTargetIDs {
		if err := requireMatch(fmt.Sprintf("affected_target_ids[%d]", i), id, reTargetID); err != nil {
			return err
		}
	}
	if f.RecommendedWorkflows == nil {
		return fmt.Errorf("recommended_workflows is required")
	}
	if f.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	return nil
}
