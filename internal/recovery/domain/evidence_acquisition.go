package domain

import (
	"fmt"
)

// ProducerType identifies what produced an evidence acquisition.
type ProducerType string

const (
	ProducerTargetResolver      ProducerType = "target_resolver"
	ProducerReadOperation       ProducerType = "read_operation"
	ProducerTechnicianSelection ProducerType = "technician_selection"
)

var producerTypes = map[string]struct{}{
	string(ProducerTargetResolver): {}, string(ProducerReadOperation): {},
	string(ProducerTechnicianSelection): {},
}

var acquisitionActors = map[string]struct{}{
	string(ActorSystem): {}, string(ActorTechnician): {},
}

// EvidenceAcquisitionRecord is an immutable provenance record for Targets and
// EvidenceBundles added after the revision-1 create/adopt event.
type EvidenceAcquisitionRecord struct {
	SchemaName       string       `json:"schema_name"`
	SchemaVersion    string       `json:"schema_version"`
	AcquisitionID    string       `json:"acquisition_id"`
	CaseID           string       `json:"case_id"`
	RequestID        string       `json:"request_id"`
	SourceCommitID   string       `json:"source_commit_id"`
	ProducerType     ProducerType `json:"producer_type"`
	ProducerID       string       `json:"producer_id"`
	ProducerVersion  string       `json:"producer_version"`
	ActorType        ActorType    `json:"actor_type"`
	AcquiredAt       string       `json:"acquired_at"`
	TargetIDs        []string     `json:"target_ids"`
	InputEvidenceIDs []string     `json:"input_evidence_ids"`
	AddedTargetIDs   []string     `json:"added_target_ids"`
	AddedEvidenceIDs []string     `json:"added_evidence_ids"`
	ParametersSHA256 string       `json:"parameters_sha256"`
	ResultSHA256     string       `json:"result_sha256"`
	Limitations      []string     `json:"limitations"`
}

func (r EvidenceAcquisitionRecord) Validate() error {
	if err := requireSchema(r.SchemaName, r.SchemaVersion, SchemaEvidenceAcquisitionRecord); err != nil {
		return err
	}
	if err := requireMatch("acquisition_id", r.AcquisitionID, reAcquisitionID); err != nil {
		return err
	}
	if err := requireMatch("case_id", r.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("request_id", r.RequestID, reAcquisitionRequestID); err != nil {
		return err
	}
	if err := requireMatch("source_commit_id", r.SourceCommitID, reCommitID); err != nil {
		return err
	}
	if err := requireEnum("producer_type", string(r.ProducerType), producerTypes); err != nil {
		return err
	}
	if err := requireMatch("producer_id", r.ProducerID, reProducerID); err != nil {
		return err
	}
	if err := requireMatch("producer_version", r.ProducerVersion, reSemver); err != nil {
		return err
	}
	if err := requireEnum("actor_type", string(r.ActorType), acquisitionActors); err != nil {
		return err
	}
	if err := requireRFC3339("acquired_at", r.AcquiredAt); err != nil {
		return err
	}
	if err := requireUniqueIDList("target_ids", r.TargetIDs, reTargetID); err != nil {
		return err
	}
	if err := requireUniqueIDList("input_evidence_ids", r.InputEvidenceIDs, reEvidenceID); err != nil {
		return err
	}
	if err := requireUniqueIDList("added_target_ids", r.AddedTargetIDs, reTargetID); err != nil {
		return err
	}
	if err := requireUniqueIDList("added_evidence_ids", r.AddedEvidenceIDs, reEvidenceID); err != nil {
		return err
	}
	if len(r.AddedTargetIDs) == 0 && len(r.AddedEvidenceIDs) == 0 {
		return fmt.Errorf("added_target_ids and added_evidence_ids must not both be empty")
	}
	if err := requireSHA256("parameters_sha256", r.ParametersSHA256); err != nil {
		return err
	}
	if err := requireSHA256("result_sha256", r.ResultSHA256); err != nil {
		return err
	}
	if r.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	for i, lim := range r.Limitations {
		if lim == "" {
			return fmt.Errorf("limitations[%d] must not be empty", i)
		}
		if len(lim) > 512 {
			return fmt.Errorf("limitations[%d] exceeds 512 characters", i)
		}
	}
	return nil
}
