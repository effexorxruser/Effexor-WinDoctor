package domain

import "fmt"

// CaseState is the lifecycle state of a recovery case.
type CaseState string

const (
	CaseStateNew                      CaseState = "NEW"
	CaseStateDiscovering              CaseState = "DISCOVERING"
	CaseStateSnapshotted              CaseState = "SNAPSHOTTED"
	CaseStateDiagnosing               CaseState = "DIAGNOSING"
	CaseStateDiagnosed                CaseState = "DIAGNOSED"
	CaseStatePlanned                  CaseState = "PLANNED"
	CaseStateAwaitingApproval         CaseState = "AWAITING_APPROVAL"
	CaseStateExecuting                CaseState = "EXECUTING"
	CaseStateVerifying                CaseState = "VERIFYING"
	CaseStateResolved                 CaseState = "RESOLVED"
	CaseStatePartiallyResolved        CaseState = "PARTIALLY_RESOLVED"
	CaseStateBlocked                  CaseState = "BLOCKED"
	CaseStateEscalated                CaseState = "ESCALATED"
	CaseStateCancelled                CaseState = "CANCELLED"
	CaseStateFailed                   CaseState = "FAILED"
	CaseStateRollbackRequired         CaseState = "ROLLBACK_REQUIRED"
	CaseStateRolledBack               CaseState = "ROLLED_BACK"
	CaseStateDataPreservationRequired CaseState = "DATA_PRESERVATION_REQUIRED"
)

var caseStates = map[string]struct{}{
	string(CaseStateNew): {}, string(CaseStateDiscovering): {}, string(CaseStateSnapshotted): {},
	string(CaseStateDiagnosing): {}, string(CaseStateDiagnosed): {}, string(CaseStatePlanned): {},
	string(CaseStateAwaitingApproval): {}, string(CaseStateExecuting): {}, string(CaseStateVerifying): {},
	string(CaseStateResolved): {}, string(CaseStatePartiallyResolved): {}, string(CaseStateBlocked): {},
	string(CaseStateEscalated): {}, string(CaseStateCancelled): {}, string(CaseStateFailed): {},
	string(CaseStateRollbackRequired): {}, string(CaseStateRolledBack): {},
	string(CaseStateDataPreservationRequired): {},
}

var privacyClasses = map[string]struct{}{
	"minimal":    {},
	"standard":   {},
	"elevated":   {},
	"restricted": {},
}

var runtimes = map[string]struct{}{
	"winpe":    {},
	"windows":  {},
	"lab_host": {},
	"unknown":  {},
}

// CaseManifest is the envelope for a recovery case.
type CaseManifest struct {
	SchemaName                 string    `json:"schema_name"`
	SchemaVersion              string    `json:"schema_version"`
	CaseID                     string    `json:"case_id"`
	CreatedAt                  string    `json:"created_at"`
	UpdatedAt                  string    `json:"updated_at"`
	Runtime                    string    `json:"runtime"`
	CurrentState               CaseState `json:"current_state"`
	TargetIDs                  []string  `json:"target_ids"`
	PrivacyClass               string    `json:"privacy_class"`
	TechnicianStorageReference string    `json:"technician_storage_reference,omitempty"`
}

func (c CaseManifest) Validate() error {
	if err := requireSchema(c.SchemaName, c.SchemaVersion, SchemaCaseManifest); err != nil {
		return err
	}
	if err := requireMatch("case_id", c.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireRFC3339("created_at", c.CreatedAt); err != nil {
		return err
	}
	if err := requireRFC3339("updated_at", c.UpdatedAt); err != nil {
		return err
	}
	if err := requireEnum("runtime", c.Runtime, runtimes); err != nil {
		return err
	}
	if err := requireEnum("current_state", string(c.CurrentState), caseStates); err != nil {
		return err
	}
	if c.TargetIDs == nil {
		return fmt.Errorf("target_ids is required")
	}
	for i, id := range c.TargetIDs {
		if err := requireMatch(fmt.Sprintf("target_ids[%d]", i), id, reTargetID); err != nil {
			return err
		}
	}
	if err := requireEnum("privacy_class", c.PrivacyClass, privacyClasses); err != nil {
		return err
	}
	if c.TechnicianStorageReference != "" {
		if err := validateRelativePath("technician_storage_reference", c.TechnicianStorageReference); err != nil {
			return err
		}
	}
	return nil
}
