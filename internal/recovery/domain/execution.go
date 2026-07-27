package domain

import (
	"fmt"
	"strings"
)

// ExecutionEvent is an audit record for a typed operation attempt.
//
// Lifecycle policy:
//   - status=started: completed_at must be absent/null and exit_code must be null
//   - terminal statuses (succeeded/failed/cancelled/timed_out): completed_at required
//   - succeeded: error must be absent or empty
//   - failed/timed_out: error must be non-empty
//   - cancelled: error optional
type ExecutionEvent struct {
	SchemaName       string   `json:"schema_name"`
	SchemaVersion    string   `json:"schema_version"`
	ExecutionID      string   `json:"execution_id"`
	CaseID           string   `json:"case_id"`
	OperationID      string   `json:"operation_id"`
	OperationVersion string   `json:"operation_version"`
	TargetID         string   `json:"target_id"`
	StartedAt        string   `json:"started_at"`
	CompletedAt      *string  `json:"completed_at"`
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

var terminalExecutionStatuses = map[string]struct{}{
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
	return e.validateLifecycle()
}

func (e ExecutionEvent) validateLifecycle() error {
	switch e.Status {
	case "started":
		if e.CompletedAt != nil {
			return fmt.Errorf("status=started requires completed_at to be null/absent")
		}
		if e.ExitCode != nil {
			return fmt.Errorf("status=started requires exit_code to be null")
		}
	default:
		if _, ok := terminalExecutionStatuses[e.Status]; !ok {
			return fmt.Errorf("status %q is not a known terminal status", e.Status)
		}
		if e.CompletedAt == nil || strings.TrimSpace(*e.CompletedAt) == "" {
			return fmt.Errorf("terminal status %q requires completed_at", e.Status)
		}
		if err := requireRFC3339("completed_at", *e.CompletedAt); err != nil {
			return err
		}
	}

	switch e.Status {
	case "succeeded":
		if strings.TrimSpace(e.Error) != "" {
			return fmt.Errorf("status=succeeded requires error to be empty/absent")
		}
	case "failed", "timed_out":
		if strings.TrimSpace(e.Error) == "" {
			return fmt.Errorf("status=%s requires a non-empty error", e.Status)
		}
	}
	return nil
}
