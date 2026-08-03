package domain

import (
	"fmt"
	"strings"
)

// AgentConsultation is an advisory, model-authored enrichment of a Recovery Case.
// It is not a deterministic Finding and never grants mutation or approval authority.
type AgentConsultation struct {
	SchemaName           string               `json:"schema_name"`
	SchemaVersion        string               `json:"schema_version"`
	ConsultationID       string               `json:"consultation_id"`
	CaseID               string               `json:"case_id"`
	RequestID            string               `json:"request_id"`
	RuntimeID            string               `json:"runtime_id"`
	RuntimeVersion       string               `json:"runtime_version"`
	SourceCommitID       string               `json:"source_commit_id"`
	InputDigest          string               `json:"input_digest"`
	GeneratedAt          string               `json:"generated_at"`
	Status               string               `json:"status"`
	RoundCount           int                  `json:"round_count"`
	TopologyID           string               `json:"topology_id,omitempty"`
	FindingRefs          []string             `json:"finding_refs"`
	EvidenceRefs         []string             `json:"evidence_refs"`
	TargetRefs           []string             `json:"target_refs"`
	Hypotheses           []AdvisoryHypothesis `json:"hypotheses"`
	NextDiagnosticSteps  []string             `json:"next_diagnostic_steps"`
	RetrievedSources     []RetrievedSource    `json:"retrieved_sources"`
	Limitations          []string             `json:"limitations"`
	ProviderMetadata     ProviderMetadata     `json:"provider_metadata"`
	InsufficientEvidence bool                 `json:"insufficient_evidence,omitempty"`
}

// AdvisoryHypothesis is an explicitly model-authored advisory claim.
type AdvisoryHypothesis struct {
	HypothesisID              string   `json:"hypothesis_id"`
	Code                      string   `json:"code"`
	Title                     string   `json:"title"`
	Rationale                 string   `json:"rationale"`
	Confidence                string   `json:"confidence"`
	SupportingFindingRefs     []string `json:"supporting_finding_refs"`
	SupportingEvidenceRefs    []string `json:"supporting_evidence_refs"`
	ContradictingEvidenceRefs []string `json:"contradicting_evidence_refs"`
	Limitations               []string `json:"limitations"`
	Advisory                  bool     `json:"advisory"`
}

// RetrievedSource is an HTTPS source actually returned by the provider adapter.
type RetrievedSource struct {
	URL    string `json:"url"`
	Domain string `json:"domain"`
	Title  string `json:"title,omitempty"`
}

// ProviderMetadata carries non-secret provider identification.
type ProviderMetadata struct {
	ProviderName string `json:"provider_name"`
	ModelName    string `json:"model_name,omitempty"`
}

var consultationStatuses = map[string]struct{}{
	"completed":           {},
	"needs_more_evidence": {},
	"blocked":             {},
	"failed":              {},
}

var hypothesisConfidences = map[string]struct{}{
	"low": {}, "medium": {}, "high": {},
}

func (c AgentConsultation) Validate() error {
	if err := requireSchema(c.SchemaName, c.SchemaVersion, SchemaAgentConsultation); err != nil {
		return err
	}
	if err := requireMatch("consultation_id", c.ConsultationID, reConsultationID); err != nil {
		return err
	}
	if err := requireMatch("case_id", c.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("request_id", c.RequestID, reConsultationRequestID); err != nil {
		return err
	}
	if err := requireNonEmpty("runtime_id", c.RuntimeID); err != nil {
		return err
	}
	if err := requireMatch("runtime_version", c.RuntimeVersion, reSemver); err != nil {
		return err
	}
	if err := requireMatch("source_commit_id", c.SourceCommitID, reCommitID); err != nil {
		return err
	}
	if err := requireSHA256("input_digest", c.InputDigest); err != nil {
		return err
	}
	if err := requireRFC3339("generated_at", c.GeneratedAt); err != nil {
		return err
	}
	if err := requireEnum("status", c.Status, consultationStatuses); err != nil {
		return err
	}
	if c.RoundCount < 1 || c.RoundCount > 3 {
		return fmt.Errorf("round_count must be between 1 and 3")
	}
	if c.TopologyID != "" {
		if err := requireMatch("topology_id", c.TopologyID, reTopologyID); err != nil {
			return err
		}
	}
	if c.FindingRefs == nil || c.EvidenceRefs == nil || c.TargetRefs == nil {
		return fmt.Errorf("finding_refs, evidence_refs, and target_refs are required")
	}
	if c.Hypotheses == nil || c.NextDiagnosticSteps == nil || c.RetrievedSources == nil || c.Limitations == nil {
		return fmt.Errorf("hypotheses, next_diagnostic_steps, retrieved_sources, and limitations are required")
	}
	if len(c.Limitations) == 0 || len(c.Limitations) > 16 {
		return fmt.Errorf("limitations must contain between 1 and 16 entries")
	}
	if len(c.FindingRefs) == 0 && len(c.EvidenceRefs) == 0 && !c.InsufficientEvidence {
		return fmt.Errorf("consultation without finding_refs and evidence_refs must set insufficient_evidence=true")
	}
	for i, id := range c.FindingRefs {
		if err := requireMatch(fmt.Sprintf("finding_refs[%d]", i), id, reFindingID); err != nil {
			return err
		}
	}
	for i, id := range c.EvidenceRefs {
		if err := requireMatch(fmt.Sprintf("evidence_refs[%d]", i), id, reEvidenceID); err != nil {
			return err
		}
	}
	for i, id := range c.TargetRefs {
		if err := requireMatch(fmt.Sprintf("target_refs[%d]", i), id, reTargetID); err != nil {
			return err
		}
	}
	if len(c.Hypotheses) > 8 {
		return fmt.Errorf("hypotheses exceeds 8 entries")
	}
	seenHyp := map[string]struct{}{}
	for i, h := range c.Hypotheses {
		if err := h.Validate(fmt.Sprintf("hypotheses[%d]", i)); err != nil {
			return err
		}
		if _, ok := seenHyp[h.HypothesisID]; ok {
			return fmt.Errorf("duplicate hypothesis_id %q", h.HypothesisID)
		}
		seenHyp[h.HypothesisID] = struct{}{}
	}
	if len(c.NextDiagnosticSteps) > 8 {
		return fmt.Errorf("next_diagnostic_steps exceeds 8 entries")
	}
	seenStep := map[string]struct{}{}
	for i, step := range c.NextDiagnosticSteps {
		if err := requireMatch(fmt.Sprintf("next_diagnostic_steps[%d]", i), step, reOperationID); err != nil {
			return err
		}
		if _, ok := seenStep[step]; ok {
			return fmt.Errorf("duplicate next_diagnostic_steps entry %q", step)
		}
		seenStep[step] = struct{}{}
	}
	if len(c.RetrievedSources) > 16 {
		return fmt.Errorf("retrieved_sources exceeds 16 entries")
	}
	for i, src := range c.RetrievedSources {
		if err := src.Validate(fmt.Sprintf("retrieved_sources[%d]", i)); err != nil {
			return err
		}
	}
	if err := requireNonEmpty("provider_metadata.provider_name", c.ProviderMetadata.ProviderName); err != nil {
		return err
	}
	return nil
}

func (h AdvisoryHypothesis) Validate(prefix string) error {
	if err := requireMatch(prefix+".hypothesis_id", h.HypothesisID, reHypothesisID); err != nil {
		return err
	}
	if err := requireMatch(prefix+".code", h.Code, reReasonCode); err != nil {
		return err
	}
	if err := requireNonEmpty(prefix+".title", h.Title); err != nil {
		return err
	}
	if err := requireNonEmpty(prefix+".rationale", h.Rationale); err != nil {
		return err
	}
	if err := requireEnum(prefix+".confidence", h.Confidence, hypothesisConfidences); err != nil {
		return err
	}
	if !h.Advisory {
		return fmt.Errorf("%s.advisory must be true", prefix)
	}
	if h.SupportingFindingRefs == nil {
		return fmt.Errorf("%s.supporting_finding_refs is required", prefix)
	}
	if h.SupportingEvidenceRefs == nil {
		return fmt.Errorf("%s.supporting_evidence_refs is required", prefix)
	}
	if h.ContradictingEvidenceRefs == nil {
		return fmt.Errorf("%s.contradicting_evidence_refs is required", prefix)
	}
	if h.Limitations == nil {
		return fmt.Errorf("%s.limitations is required", prefix)
	}
	for i, id := range h.SupportingFindingRefs {
		if err := requireMatch(fmt.Sprintf("%s.supporting_finding_refs[%d]", prefix, i), id, reFindingID); err != nil {
			return err
		}
	}
	for i, id := range h.SupportingEvidenceRefs {
		if err := requireMatch(fmt.Sprintf("%s.supporting_evidence_refs[%d]", prefix, i), id, reEvidenceID); err != nil {
			return err
		}
	}
	for i, id := range h.ContradictingEvidenceRefs {
		if err := requireMatch(fmt.Sprintf("%s.contradicting_evidence_refs[%d]", prefix, i), id, reEvidenceID); err != nil {
			return err
		}
	}
	return nil
}

func (s RetrievedSource) Validate(prefix string) error {
	if err := requireNonEmpty(prefix+".url", s.URL); err != nil {
		return err
	}
	if len(s.URL) < 12 || !hasHTTPSPrefix(s.URL) {
		return fmt.Errorf("%s.url must be https", prefix)
	}
	if err := requireNonEmpty(prefix+".domain", s.Domain); err != nil {
		return err
	}
	return nil
}

func hasHTTPSPrefix(u string) bool {
	return strings.HasPrefix(strings.ToLower(u), "https://")
}

// ValidateConsultationRefs checks consultation finding/evidence/target refs against known IDs.
func (c AgentConsultation) ValidateConsultationRefs(refs CrossRefs) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if _, ok := refs.CaseIDs[c.CaseID]; !ok {
		return fmt.Errorf("case_id %q is not in the snapshot", c.CaseID)
	}
	for _, id := range c.FindingRefs {
		if _, ok := refs.FindingIDs[id]; !ok {
			return fmt.Errorf("finding_refs contains unknown finding_id %q", id)
		}
	}
	for _, id := range c.EvidenceRefs {
		if _, ok := refs.EvidenceIDs[id]; !ok {
			return fmt.Errorf("evidence_refs contains unknown evidence_id %q", id)
		}
	}
	for _, id := range c.TargetRefs {
		if _, ok := refs.TargetIDs[id]; !ok {
			return fmt.Errorf("target_refs contains unknown target_id %q", id)
		}
	}
	for _, h := range c.Hypotheses {
		for _, id := range h.SupportingFindingRefs {
			if _, ok := refs.FindingIDs[id]; !ok {
				return fmt.Errorf("hypothesis %q supporting_finding_refs contains unknown finding_id %q", h.HypothesisID, id)
			}
		}
		for _, id := range h.SupportingEvidenceRefs {
			if _, ok := refs.EvidenceIDs[id]; !ok {
				return fmt.Errorf("hypothesis %q supporting_evidence_refs contains unknown evidence_id %q", h.HypothesisID, id)
			}
		}
		for _, id := range h.ContradictingEvidenceRefs {
			if _, ok := refs.EvidenceIDs[id]; !ok {
				return fmt.Errorf("hypothesis %q contradicting_evidence_refs contains unknown evidence_id %q", h.HypothesisID, id)
			}
		}
	}
	return nil
}
