package domain

import "fmt"

// ExecutionEvent is an audit record for a typed operation attempt.
type ExecutionEvent struct {
	SchemaName       string   `json:"schema_name"`
	SchemaVersion    string   `json:"schema_version"`
	ExecutionID      string   `json:"execution_id"`
	CaseID           string   `json:"case_id"`
	OperationID      string   `json:"operation_id"`
	OperationVersion string   `json:"operation_version"`
	TargetID         string   `json:"target_id"`
	StartedAt        string   `json:"started_at"`
	CompletedAt      string   `json:"completed_at"`
	Status           string   `json:"status"`
	ExitCode         *int     `json:"exit_code"`
	StdoutArtifact   string   `json:"stdout_artifact,omitempty"`
	StderrArtifact   string   `json:"stderr_artifact,omitempty"`
	ChangedResources []string `json:"changed_resources"`
	Error            string   `json:"error,omitempty"`
}

var executionStatuses = map[string]struct{}{
	"started":   {},
	"succeeded": {},
	"failed":    {},
	"cancelled": {},
	"timed_out": {},
}

func (e ExecutionEvent) Validate() error {
	if err := requireSchema(e.SchemaName, e.SchemaVersion, SchemaExecutionEvent); err != nil {
		return err
	}
	if err := requireMatch("execution_id", e.ExecutionID, reExecutionID); err != nil {
		return err
	}
	if err := requireMatch("case_id", e.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("operation_id", e.OperationID, reOperationID); err != nil {
		return err
	}
	if !reSemver.MatchString(e.OperationVersion) {
		return fmt.Errorf("operation_version must be semver MAJOR.MINOR.PATCH")
	}
	if err := requireMatch("target_id", e.TargetID, reTargetID); err != nil {
		return err
	}
	if err := requireRFC3339("started_at", e.StartedAt); err != nil {
		return err
	}
	if err := requireRFC3339("completed_at", e.CompletedAt); err != nil {
		return err
	}
	if err := requireEnum("status", e.Status, executionStatuses); err != nil {
		return err
	}
	if e.StdoutArtifact != "" {
		if err := requireMatch("stdout_artifact", e.StdoutArtifact, reArtifactID); err != nil {
			return err
		}
	}
	if e.StderrArtifact != "" {
		if err := requireMatch("stderr_artifact", e.StderrArtifact, reArtifactID); err != nil {
			return err
		}
	}
	if e.ChangedResources == nil {
		return fmt.Errorf("changed_resources is required")
	}
	return nil
}
