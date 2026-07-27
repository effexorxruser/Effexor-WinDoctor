package domain

import (
	"encoding/json"
	"fmt"
)

// RiskClass classifies operation risk.
type RiskClass string

const (
	RiskReadOnly           RiskClass = "read_only"
	RiskReversible         RiskClass = "reversible"
	RiskControlledMutation RiskClass = "controlled_mutation"
	RiskDestructive        RiskClass = "destructive"
	RiskIrreversible       RiskClass = "irreversible"
)

// RollbackQuality describes rollback expectations.
type RollbackQuality string

const (
	RollbackExact        RollbackQuality = "exact"
	RollbackBestEffort   RollbackQuality = "best_effort"
	RollbackCompensating RollbackQuality = "compensating"
	RollbackUnavailable  RollbackQuality = "unavailable"
)

var riskClasses = map[string]struct{}{
	string(RiskReadOnly): {}, string(RiskReversible): {}, string(RiskControlledMutation): {},
	string(RiskDestructive): {}, string(RiskIrreversible): {},
}

var rollbackQualities = map[string]struct{}{
	string(RollbackExact): {}, string(RollbackBestEffort): {},
	string(RollbackCompensating): {}, string(RollbackUnavailable): {},
}

var mutationClasses = map[string]struct{}{
	"none":     {},
	"metadata": {},
	"config":   {},
	"data":     {},
	"firmware": {},
}

// OperationDescriptor describes a typed operation. It must not contain command strings.
type OperationDescriptor struct {
	SchemaName               string          `json:"schema_name"`
	SchemaVersion            string          `json:"schema_version"`
	OperationID              string          `json:"operation_id"`
	Version                  string          `json:"version"`
	Title                    string          `json:"title"`
	Description              string          `json:"description"`
	Module                   string          `json:"module"`
	RiskClass                RiskClass       `json:"risk_class"`
	MutationClass            string          `json:"mutation_class"`
	RequiredEvidence         []string        `json:"required_evidence"`
	RequiredCapabilities     []string        `json:"required_capabilities"`
	SupportedRuntimes        []string        `json:"supported_runtimes"`
	RequiresBackup           bool            `json:"requires_backup"`
	RollbackQuality          RollbackQuality `json:"rollback_quality"`
	RequiresExplicitApproval bool            `json:"requires_explicit_approval"`
	ParametersSchemaRef      string          `json:"parameters_schema_ref"`
	ResultSchemaRef          string          `json:"result_schema_ref"`
}

func (o OperationDescriptor) Validate() error {
	if err := requireSchema(o.SchemaName, o.SchemaVersion, SchemaOperationDescriptor); err != nil {
		return err
	}
	if err := requireMatch("operation_id", o.OperationID, reOperationID); err != nil {
		return err
	}
	if !reSemver.MatchString(o.Version) {
		return fmt.Errorf("version must be semver MAJOR.MINOR.PATCH")
	}
	if err := requireNonEmpty("title", o.Title); err != nil {
		return err
	}
	if err := requireNonEmpty("description", o.Description); err != nil {
		return err
	}
	if err := requireNonEmpty("module", o.Module); err != nil {
		return err
	}
	if err := requireEnum("risk_class", string(o.RiskClass), riskClasses); err != nil {
		return err
	}
	if err := requireEnum("mutation_class", o.MutationClass, mutationClasses); err != nil {
		return err
	}
	if o.RequiredEvidence == nil {
		return fmt.Errorf("required_evidence is required")
	}
	if o.RequiredCapabilities == nil {
		return fmt.Errorf("required_capabilities is required")
	}
	if o.SupportedRuntimes == nil || len(o.SupportedRuntimes) == 0 {
		return fmt.Errorf("supported_runtimes must be non-empty")
	}
	for i, rt := range o.SupportedRuntimes {
		if err := requireEnum(fmt.Sprintf("supported_runtimes[%d]", i), rt, runtimes); err != nil {
			return err
		}
	}
	if err := requireEnum("rollback_quality", string(o.RollbackQuality), rollbackQualities); err != nil {
		return err
	}
	if err := requireNonEmpty("parameters_schema_ref", o.ParametersSchemaRef); err != nil {
		return err
	}
	if err := requireNonEmpty("result_schema_ref", o.ResultSchemaRef); err != nil {
		return err
	}
	return nil
}

// DecodeOperationDescriptorStrict rejects unknown and forbidden command-like fields.
func DecodeOperationDescriptorStrict(raw []byte) (OperationDescriptor, error) {
	var probe map[string]json.RawMessage
	dec := json.NewDecoder(bytesReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&probe); err != nil {
		return OperationDescriptor{}, err
	}
	forbidden := []string{
		"command", "commands", "powershell", "ps1", "shell", "executable",
		"exe", "argv", "args", "script", "cmdline", "cmd",
	}
	for _, key := range forbidden {
		if _, ok := probe[key]; ok {
			return OperationDescriptor{}, fmt.Errorf("forbidden field %q is not allowed on OperationDescriptor", key)
		}
	}
	var out OperationDescriptor
	if err := strictDecode(raw, &out); err != nil {
		return OperationDescriptor{}, err
	}
	if err := out.Validate(); err != nil {
		return OperationDescriptor{}, err
	}
	return out, nil
}
