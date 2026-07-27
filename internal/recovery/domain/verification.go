package domain

import "fmt"

// ConditionCheck is one expected or observed verification condition.
type ConditionCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

var conditionStatuses = map[string]struct{}{
	"met":         {},
	"not_met":     {},
	"unavailable": {},
}

func (c ConditionCheck) Validate(field string) error {
	if err := requireNonEmpty(field+".name", c.Name); err != nil {
		return err
	}
	if err := requireEnum(field+".status", c.Status, conditionStatuses); err != nil {
		return err
	}
	return nil
}

// VerificationReport records post-operation verification.
type VerificationReport struct {
	SchemaName         string           `json:"schema_name"`
	SchemaVersion      string           `json:"schema_version"`
	VerificationID     string           `json:"verification_id"`
	CaseID             string           `json:"case_id"`
	ExecutionID        string           `json:"execution_id"`
	Verifier           string           `json:"verifier"`
	VerifiedAt         string           `json:"verified_at"`
	ExpectedConditions []ConditionCheck `json:"expected_conditions"`
	ObservedConditions []ConditionCheck `json:"observed_conditions"`
	Status             string           `json:"status"`
	Regressions        []string         `json:"regressions"`
	RemainingRisks     []string         `json:"remaining_risks"`
	EvidenceRefs       []string         `json:"evidence_refs"`
}

var verificationStatuses = map[string]struct{}{
	"resolved":           {},
	"partially_resolved": {},
	"not_resolved":       {},
	"regressed":          {},
	"inconclusive":       {},
}

func (v VerificationReport) Validate() error {
	if err := requireSchema(v.SchemaName, v.SchemaVersion, SchemaVerificationReport); err != nil {
		return err
	}
	if err := requireMatch("verification_id", v.VerificationID, reVerificationID); err != nil {
		return err
	}
	if err := requireMatch("case_id", v.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("execution_id", v.ExecutionID, reExecutionID); err != nil {
		return err
	}
	if err := requireNonEmpty("verifier", v.Verifier); err != nil {
		return err
	}
	if err := requireRFC3339("verified_at", v.VerifiedAt); err != nil {
		return err
	}
	if v.ExpectedConditions == nil {
		return fmt.Errorf("expected_conditions is required")
	}
	for i, c := range v.ExpectedConditions {
		if err := c.Validate(fmt.Sprintf("expected_conditions[%d]", i)); err != nil {
			return err
		}
	}
	if v.ObservedConditions == nil {
		return fmt.Errorf("observed_conditions is required")
	}
	for i, c := range v.ObservedConditions {
		if err := c.Validate(fmt.Sprintf("observed_conditions[%d]", i)); err != nil {
			return err
		}
	}
	if err := requireEnum("status", v.Status, verificationStatuses); err != nil {
		return err
	}
	if v.Regressions == nil {
		return fmt.Errorf("regressions is required")
	}
	if v.RemainingRisks == nil {
		return fmt.Errorf("remaining_risks is required")
	}
	if v.EvidenceRefs == nil {
		return fmt.Errorf("evidence_refs is required")
	}
	for i, id := range v.EvidenceRefs {
		if err := requireMatch(fmt.Sprintf("evidence_refs[%d]", i), id, reEvidenceID); err != nil {
			return err
		}
	}
	return nil
}
