package agentruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/agentloop"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
)

// ValidateProposal enforces the strict provider contract (fail closed).
func ValidateProposal(proposal ProviderProposal, snap casestore.Snapshot, round int, maxRounds int) error {
	raw, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	if len(raw) > MaxResponseBytes {
		return fmt.Errorf("provider proposal exceeds max response bytes")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var again ProviderProposal
	if err := dec.Decode(&again); err != nil {
		return fmt.Errorf("provider proposal json: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return err
	}

	if proposal.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", proposal.SchemaVersion)
	}
	if proposal.CaseID != snap.Case.CaseID {
		return fmt.Errorf("proposal case_id mismatch")
	}
	if proposal.Round != round {
		return fmt.Errorf("proposal round mismatch")
	}
	if round < 1 || round > maxRounds {
		return fmt.Errorf("round out of bounds")
	}
	switch proposal.Status {
	case StatusCompleted, StatusNeedsMoreEvidence, StatusBlocked, StatusFailed:
	default:
		return fmt.Errorf("invalid status %q", proposal.Status)
	}
	if proposal.Hypotheses == nil || proposal.ReadRequests == nil || proposal.NextDiagnosticSteps == nil ||
		proposal.RetrievedSources == nil || proposal.Limitations == nil {
		return fmt.Errorf("required proposal arrays must be present")
	}
	if strings.TrimSpace(proposal.ProviderName) == "" {
		return fmt.Errorf("provider_name is required")
	}
	if len(proposal.Hypotheses) > MaxHypotheses {
		return fmt.Errorf("too many hypotheses")
	}
	if len(proposal.RetrievedSources) > MaxSources {
		return fmt.Errorf("too many retrieved_sources")
	}
	if len(proposal.Limitations) == 0 || len(proposal.Limitations) > MaxLimitations {
		return fmt.Errorf("limitations must contain 1..%d entries", MaxLimitations)
	}
	if proposal.Status == StatusNeedsMoreEvidence && len(proposal.ReadRequests) == 0 {
		return fmt.Errorf("needs_more_evidence requires read_requests")
	}
	if proposal.Status != StatusNeedsMoreEvidence && len(proposal.ReadRequests) != 0 {
		return fmt.Errorf("read_requests only allowed for needs_more_evidence")
	}

	findingIDs := map[string]struct{}{}
	for _, f := range snap.Findings {
		findingIDs[f.FindingID] = struct{}{}
	}
	evidenceIDs := map[string]struct{}{}
	for _, e := range snap.EvidenceBundles {
		evidenceIDs[e.EvidenceID] = struct{}{}
	}

	providerURLs := map[string]struct{}{}
	for i, src := range proposal.RetrievedSources {
		normalized, _, err := ValidateHTTPSSource(src.URL)
		if err != nil {
			return fmt.Errorf("retrieved_sources[%d]: %w", i, err)
		}
		providerURLs[normalized] = struct{}{}
		_ = normalized
		if strings.TrimSpace(src.Domain) == "" {
			return fmt.Errorf("retrieved_sources[%d].domain is required", i)
		}
	}

	for i, h := range proposal.Hypotheses {
		if err := requireNonEmpty(fmt.Sprintf("hypotheses[%d].code", i), h.Code); err != nil {
			return err
		}
		if err := requireNonEmpty(fmt.Sprintf("hypotheses[%d].title", i), h.Title); err != nil {
			return err
		}
		if err := requireNonEmpty(fmt.Sprintf("hypotheses[%d].rationale", i), h.Rationale); err != nil {
			return err
		}
		switch h.Confidence {
		case "low", "medium", "high":
		default:
			return fmt.Errorf("hypotheses[%d].confidence invalid", i)
		}
		if h.SupportingFindingRefs == nil || h.SupportingEvidenceRefs == nil || h.ContradictingEvidenceRefs == nil || h.Limitations == nil {
			return fmt.Errorf("hypotheses[%d] required arrays missing", i)
		}
		for _, id := range h.SupportingFindingRefs {
			if _, ok := findingIDs[id]; !ok {
				return fmt.Errorf("hypotheses[%d] unknown finding ref %q", i, id)
			}
		}
		for _, id := range h.SupportingEvidenceRefs {
			if _, ok := evidenceIDs[id]; !ok {
				return fmt.Errorf("hypotheses[%d] unknown evidence ref %q", i, id)
			}
		}
		for _, id := range h.ContradictingEvidenceRefs {
			if _, ok := evidenceIDs[id]; !ok {
				return fmt.Errorf("hypotheses[%d] unknown contradicting evidence ref %q", i, id)
			}
		}
		// Rationale may mention historical tool names; reject only executable-like fields.
		if err := agentloop.RejectCommandText(fmt.Sprintf("hypotheses[%d].code", i), h.Code); err != nil {
			return err
		}
		if err := rejectApprovalClaims(fmt.Sprintf("hypotheses[%d].title", i), h.Title); err != nil {
			return err
		}
		if err := rejectApprovalClaims(fmt.Sprintf("hypotheses[%d].rationale", i), h.Rationale); err != nil {
			return err
		}
	}

	for i, step := range proposal.NextDiagnosticSteps {
		if err := requireNonEmpty(fmt.Sprintf("next_diagnostic_steps[%d]", i), step); err != nil {
			return err
		}
	}
	for i, lim := range proposal.Limitations {
		if err := requireNonEmpty(fmt.Sprintf("limitations[%d]", i), lim); err != nil {
			return err
		}
		if err := rejectApprovalClaims(fmt.Sprintf("limitations[%d]", i), lim); err != nil {
			return err
		}
	}
	_ = providerURLs
	return nil
}

func ensureEOF(dec *json.Decoder) error {
	if dec.More() {
		return fmt.Errorf("trailing json content")
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return fmt.Errorf("trailing json content")
	}
	return nil
}

func requireNonEmpty(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func rejectApprovalClaims(field, value string) error {
	lower := strings.ToLower(value)
	banned := []string{
		"approved for repair", "repair approved", "mutation authorized",
		"execute repair", "clear blocker", "plan_proposed",
	}
	for _, b := range banned {
		if strings.Contains(lower, b) {
			return fmt.Errorf("%s contains forbidden authority claim", field)
		}
	}
	return nil
}
