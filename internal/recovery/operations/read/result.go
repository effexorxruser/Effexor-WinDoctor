package read

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// Result is the typed observation envelope produced by Execute.
type Result struct {
	domain.ReadOperationResult
}

// Read returns the embedded domain result.
func (r Result) Read() domain.ReadOperationResult {
	return r.ReadOperationResult
}

// EvidenceFromResult converts a read operation result into an EvidenceBundle with a
// deterministic evidence_id derived from case, operation, target, source evidence,
// and canonical result bytes (observed_at is excluded from the identity hash).
func EvidenceFromResult(result domain.ReadOperationResult, collectorVersion string) (domain.EvidenceBundle, error) {
	if err := result.Validate(); err != nil {
		return domain.EvidenceBundle{}, fmt.Errorf("result: %w", err)
	}
	if collectorVersion == "" {
		collectorVersion = collectorVersionDefault()
	}
	facts, err := json.Marshal(result)
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	evidenceID, err := evidenceIDFromResult(result, facts)
	if err != nil {
		return domain.EvidenceBundle{}, err
	}
	return domain.EvidenceBundle{
		SchemaName:       domain.SchemaEvidenceBundle,
		SchemaVersion:    domain.SchemaVersion,
		EvidenceID:       evidenceID,
		CaseID:           result.CaseID,
		TargetID:         result.TargetID,
		Collector:        collectorName,
		CollectorVersion: collectorVersion,
		CapturedAt:       result.ObservedAt,
		SourceStatus:     mapResultStatus(result.Status),
		FactsSchema:      domain.SchemaReadOperationResult,
		Facts:            facts,
		Artifacts:        []domain.ArtifactRef{},
		Limitations:      append([]string(nil), result.Limitations...),
	}, nil
}

func collectorVersionDefault() string {
	return collectorVersion
}

func mapResultStatus(status domain.ReadObservationStatus) string {
	switch status {
	case domain.ReadStatusOK:
		return "ok"
	case domain.ReadStatusPartial:
		return "partial"
	case domain.ReadStatusUnavailable:
		return "unavailable"
	case domain.ReadStatusError:
		return "error"
	default:
		return "error"
	}
}

func evidenceIDFromResult(result domain.ReadOperationResult, canonicalFacts []byte) (string, error) {
	type identity struct {
		CaseID            string   `json:"case_id"`
		OperationID       string   `json:"operation_id"`
		OperationVersion  string   `json:"operation_version"`
		TargetID          string   `json:"target_id"`
		SourceEvidenceIDs []string `json:"source_evidence_ids"`
		FactsSHA256       string   `json:"facts_sha256"`
	}
	clone := result
	clone.ObservedAt = ""
	factsForHash, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(factsForHash)
	payload, err := json.Marshal(identity{
		CaseID:            result.CaseID,
		OperationID:       result.OperationID,
		OperationVersion:  result.OperationVersion,
		TargetID:          result.TargetID,
		SourceEvidenceIDs: sortedCopy(result.SourceEvidenceIDs),
		FactsSHA256:       hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return "", err
	}
	idSum := sha256.Sum256(payload)
	return "evidence-" + hex.EncodeToString(idSum[:12]), nil
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func marshalFacts(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}
