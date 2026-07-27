package domain

import (
	"encoding/json"
	"fmt"
)

// EvidenceBundle is a collector-produced evidence document for one target.
// facts is an intentional extension point for collector-specific payloads.
type EvidenceBundle struct {
	SchemaName       string          `json:"schema_name"`
	SchemaVersion    string          `json:"schema_version"`
	EvidenceID       string          `json:"evidence_id"`
	CaseID           string          `json:"case_id"`
	TargetID         string          `json:"target_id"`
	Collector        string          `json:"collector"`
	CollectorVersion string          `json:"collector_version"`
	CapturedAt       string          `json:"captured_at"`
	SourceStatus     string          `json:"source_status"`
	FactsSchema      string          `json:"facts_schema,omitempty"`
	Facts            json.RawMessage `json:"facts"`
	Artifacts        []ArtifactRef   `json:"artifacts"`
	Limitations      []string        `json:"limitations"`
}

var sourceStatuses = map[string]struct{}{
	"ok":          {},
	"partial":     {},
	"unavailable": {},
	"error":       {},
}

func (e EvidenceBundle) Validate() error {
	if err := requireSchema(e.SchemaName, e.SchemaVersion, SchemaEvidenceBundle); err != nil {
		return err
	}
	if err := requireMatch("evidence_id", e.EvidenceID, reEvidenceID); err != nil {
		return err
	}
	if err := requireMatch("case_id", e.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("target_id", e.TargetID, reTargetID); err != nil {
		return err
	}
	if err := requireNonEmpty("collector", e.Collector); err != nil {
		return err
	}
	if err := requireNonEmpty("collector_version", e.CollectorVersion); err != nil {
		return err
	}
	if err := requireRFC3339("captured_at", e.CapturedAt); err != nil {
		return err
	}
	if err := requireEnum("source_status", e.SourceStatus, sourceStatuses); err != nil {
		return err
	}
	if len(e.Facts) == 0 {
		return fmt.Errorf("facts is required")
	}
	if !json.Valid(e.Facts) {
		return fmt.Errorf("facts must be valid JSON")
	}
	if e.Artifacts == nil {
		return fmt.Errorf("artifacts is required")
	}
	for i, a := range e.Artifacts {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", i, err)
		}
	}
	if e.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	return nil
}
