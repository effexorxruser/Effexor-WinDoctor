package agentruntime

import (
	"context"
	"encoding/json"
)

// RoundProvider proposes one consultation turn using only sanitized context.
type RoundProvider interface {
	Propose(ctx context.Context, input RoundInput) (ProviderProposal, error)
}

// RoundInput is the sanitized provider-visible payload for one round.
type RoundInput struct {
	Context          SanitizedRecoveryContext `json:"context"`
	Round            int                      `json:"round"`
	PriorEvidence    []SanitizedEvidence      `json:"prior_evidence"`
	PriorRequestKeys []string                 `json:"prior_request_keys"`
}

// ProviderProposal is the strict provider response contract.
type ProviderProposal struct {
	SchemaVersion       string             `json:"schema_version"`
	CaseID              string             `json:"case_id"`
	Round               int                `json:"round"`
	Status              string             `json:"status"`
	Hypotheses          []HypothesisDraft  `json:"hypotheses"`
	ReadRequests        []ReadRequestDraft `json:"read_requests"`
	NextDiagnosticSteps []string           `json:"next_diagnostic_steps"`
	RetrievedSources    []SourceDraft      `json:"retrieved_sources"`
	Limitations         []string           `json:"limitations"`
	ProviderName        string             `json:"provider_name"`
	ModelName           string             `json:"model_name,omitempty"`
}

// HypothesisDraft is a model-authored advisory hypothesis proposal.
type HypothesisDraft struct {
	Code                      string   `json:"code"`
	Title                     string   `json:"title"`
	Rationale                 string   `json:"rationale"`
	Confidence                string   `json:"confidence"`
	SupportingFindingRefs     []string `json:"supporting_finding_refs"`
	SupportingEvidenceRefs    []string `json:"supporting_evidence_refs"`
	ContradictingEvidenceRefs []string `json:"contradicting_evidence_refs"`
	Limitations               []string `json:"limitations"`
}

// ReadRequestDraft proposes a typed read-only Coordinator operation.
type ReadRequestDraft struct {
	RequestKey       string          `json:"request_key"`
	OperationID      string          `json:"operation_id"`
	OperationVersion string          `json:"operation_version"`
	TargetID         string          `json:"target_id"`
	Parameters       json.RawMessage `json:"parameters"`
}

// SourceDraft is a provider-returned HTTPS source for this round.
type SourceDraft struct {
	URL    string `json:"url"`
	Domain string `json:"domain"`
	Title  string `json:"title,omitempty"`
}
