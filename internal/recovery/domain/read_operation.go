package domain

import (
	"encoding/json"
	"fmt"
)

type ReadObservationStatus string

const (
	ReadStatusOK          ReadObservationStatus = "ok"
	ReadStatusPartial     ReadObservationStatus = "partial"
	ReadStatusUnavailable ReadObservationStatus = "unavailable"
	ReadStatusError       ReadObservationStatus = "error"
)

type ObservationSource string

const (
	ObservationCaseSnapshot ObservationSource = "case_snapshot"
	ObservationCaseStore    ObservationSource = "case_store"
)

var (
	readStatuses = map[string]struct{}{
		string(ReadStatusOK): {}, string(ReadStatusPartial): {},
		string(ReadStatusUnavailable): {}, string(ReadStatusError): {},
	}
	observationSources = map[string]struct{}{
		string(ObservationCaseSnapshot): {}, string(ObservationCaseStore): {},
	}
)

// ReadOperationRequest is the typed envelope for PR #18 read-only operations.
type ReadOperationRequest struct {
	SchemaName       string          `json:"schema_name"`
	SchemaVersion    string          `json:"schema_version"`
	RequestID        string          `json:"request_id"`
	CaseID           string          `json:"case_id"`
	OperationID      string          `json:"operation_id"`
	OperationVersion string          `json:"operation_version"`
	TargetID         string          `json:"target_id"`
	Parameters       json.RawMessage `json:"parameters"`
}

// ReadOperationResult is the typed observation envelope produced by read ops.
type ReadOperationResult struct {
	SchemaName        string                `json:"schema_name"`
	SchemaVersion     string                `json:"schema_version"`
	RequestID         string                `json:"request_id"`
	CaseID            string                `json:"case_id"`
	OperationID       string                `json:"operation_id"`
	OperationVersion  string                `json:"operation_version"`
	TargetID          string                `json:"target_id"`
	ObservedAt        string                `json:"observed_at"`
	Status            ReadObservationStatus `json:"status"`
	ObservationSource ObservationSource     `json:"observation_source"`
	SourceEvidenceIDs []string              `json:"source_evidence_ids"`
	Facts             json.RawMessage       `json:"facts"`
	Limitations       []string              `json:"limitations"`
}

func (r ReadOperationRequest) Validate() error {
	if err := requireSchema(r.SchemaName, r.SchemaVersion, SchemaReadOperationRequest); err != nil {
		return err
	}
	if err := requireMatch("request_id", r.RequestID, reReadRequestID); err != nil {
		return err
	}
	if err := requireMatch("case_id", r.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("operation_id", r.OperationID, reOperationID); err != nil {
		return err
	}
	if err := requireMatch("operation_version", r.OperationVersion, reSemver); err != nil {
		return err
	}
	if err := requireMatch("target_id", r.TargetID, reTargetID); err != nil {
		return err
	}
	if len(r.Parameters) == 0 {
		return fmt.Errorf("parameters is required")
	}
	var params map[string]any
	if err := json.Unmarshal(r.Parameters, &params); err != nil {
		return fmt.Errorf("parameters: %w", err)
	}
	if err := forbiddenKeys(params, "command", "shell", "powershell", "argv", "executable", "script"); err != nil {
		return err
	}
	switch r.OperationID {
	case "boot.inspect_efi_layout", "storage.inspect_partition_layout":
		for k := range params {
			if k != "disk_target_id" {
				return fmt.Errorf("unknown parameter %q", k)
			}
		}
		if v, ok := params["disk_target_id"]; ok {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("disk_target_id must be a string")
			}
			if err := requireMatch("disk_target_id", s, reTargetID); err != nil {
				return err
			}
		}
	default:
		if len(params) != 0 {
			return fmt.Errorf("parameters must be an empty object for operation %q", r.OperationID)
		}
	}
	return nil
}

func (r ReadOperationResult) Validate() error {
	if err := requireSchema(r.SchemaName, r.SchemaVersion, SchemaReadOperationResult); err != nil {
		return err
	}
	if err := requireMatch("request_id", r.RequestID, reReadRequestID); err != nil {
		return err
	}
	if err := requireMatch("case_id", r.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("operation_id", r.OperationID, reOperationID); err != nil {
		return err
	}
	if err := requireMatch("operation_version", r.OperationVersion, reSemver); err != nil {
		return err
	}
	if err := requireMatch("target_id", r.TargetID, reTargetID); err != nil {
		return err
	}
	if err := requireRFC3339("observed_at", r.ObservedAt); err != nil {
		return err
	}
	if err := requireEnum("status", string(r.Status), readStatuses); err != nil {
		return err
	}
	if err := requireEnum("observation_source", string(r.ObservationSource), observationSources); err != nil {
		return err
	}
	if err := requireUniqueIDList("source_evidence_ids", r.SourceEvidenceIDs, reEvidenceID); err != nil {
		return err
	}
	if len(r.Facts) == 0 {
		return fmt.Errorf("facts is required")
	}
	var facts map[string]any
	if err := json.Unmarshal(r.Facts, &facts); err != nil {
		return fmt.Errorf("facts: %w", err)
	}
	if err := forbiddenKeys(facts, "command", "shell", "powershell", "argv", "executable", "script"); err != nil {
		return err
	}
	if r.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	for i, lim := range r.Limitations {
		if lim == "" {
			return fmt.Errorf("limitations[%d] must not be empty", i)
		}
	}
	return nil
}
