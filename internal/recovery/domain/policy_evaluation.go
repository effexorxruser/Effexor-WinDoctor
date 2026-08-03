package domain

import "fmt"

// PolicyEvaluation is an independent, immutable gate decision for a RepairPlan.
// It does not execute operations and does not grant execution authority.
type PolicyEvaluation struct {
	SchemaName     string   `json:"schema_name"`
	SchemaVersion  string   `json:"schema_version"`
	EvaluationID   string   `json:"evaluation_id"`
	CaseID         string   `json:"case_id"`
	RequestID      string   `json:"request_id"`
	PlanID         string   `json:"plan_id"`
	PlanDigest     string   `json:"plan_digest"`
	SourceCommitID string   `json:"source_commit_id"`
	TopologyID     string   `json:"topology_id,omitempty"`
	EvaluatedAt    string   `json:"evaluated_at"`
	Decision       string   `json:"decision"`
	ReasonCodes    []string `json:"reason_codes"`
	PolicyVersion  string   `json:"policy_version"`
	InputDigest    string   `json:"input_digest,omitempty"`
	Limitations    []string `json:"limitations"`
}

var policyDecisions = map[string]struct{}{
	"allowed":             {},
	"denied":              {},
	"needs_more_evidence": {},
}

func (p PolicyEvaluation) Validate() error {
	if err := requireSchema(p.SchemaName, p.SchemaVersion, SchemaPolicyEvaluation); err != nil {
		return err
	}
	if err := requireMatch("evaluation_id", p.EvaluationID, rePolicyEvaluationID); err != nil {
		return err
	}
	if err := requireMatch("case_id", p.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("request_id", p.RequestID, rePolicyRequestID); err != nil {
		return err
	}
	if err := requireMatch("plan_id", p.PlanID, rePlanID); err != nil {
		return err
	}
	if err := requireSHA256("plan_digest", p.PlanDigest); err != nil {
		return err
	}
	if err := requireMatch("source_commit_id", p.SourceCommitID, reCommitID); err != nil {
		return err
	}
	if p.TopologyID != "" {
		if err := requireMatch("topology_id", p.TopologyID, reTopologyID); err != nil {
			return err
		}
	}
	if err := requireRFC3339("evaluated_at", p.EvaluatedAt); err != nil {
		return err
	}
	if err := requireEnum("decision", p.Decision, policyDecisions); err != nil {
		return err
	}
	if len(p.ReasonCodes) == 0 || len(p.ReasonCodes) > 64 {
		return fmt.Errorf("reason_codes must contain between 1 and 64 entries")
	}
	seen := map[string]struct{}{}
	for i, code := range p.ReasonCodes {
		if err := requireMatch(fmt.Sprintf("reason_codes[%d]", i), code, reReasonCode); err != nil {
			return err
		}
		if _, dup := seen[code]; dup {
			return fmt.Errorf("duplicate reason_code %q", code)
		}
		seen[code] = struct{}{}
	}
	if err := requireMatch("policy_version", p.PolicyVersion, reSemver); err != nil {
		return err
	}
	if p.InputDigest != "" {
		if err := requireSHA256("input_digest", p.InputDigest); err != nil {
			return err
		}
	}
	if len(p.Limitations) == 0 || len(p.Limitations) > 32 {
		return fmt.Errorf("limitations must contain between 1 and 32 entries")
	}
	return nil
}

// ValidatePolicyEvaluationRefs checks case/plan refs.
func (p PolicyEvaluation) ValidatePolicyEvaluationRefs(refs CrossRefs) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", p.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	if err := requireRef("plan_id", p.PlanID, refs.PlanIDs); err != nil {
		return err
	}
	return nil
}
