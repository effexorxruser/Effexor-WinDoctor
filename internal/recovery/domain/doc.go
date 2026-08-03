// Package domain defines Effexor Recovery Platform document types (v1.0.0).
//
// These contracts describe recovery cases, evidence, findings, plans,
// operations, execution audits, and verification. They do not execute
// commands and do not replace diagnostic-report 1.3.0.
package domain

const SchemaVersion = "1.0.0"

// Document schema_name constants.
const (
	SchemaCaseManifest              = "case-manifest"
	SchemaTarget                    = "target"
	SchemaEvidenceBundle            = "evidence-bundle"
	SchemaFinding                   = "finding"
	SchemaRepairPlan                = "repair-plan"
	SchemaOperationDescriptor       = "operation-descriptor"
	SchemaExecutionEvent            = "execution-event"
	SchemaVerificationReport        = "verification-report"
	SchemaCaseWorkflowState         = "case-workflow-state"
	SchemaCoordinatorEvent          = "coordinator-event"
	SchemaEvidenceAcquisitionRecord = "evidence-acquisition-record"
	SchemaWindowsBootTopology       = "windows-boot-topology"
	SchemaReadOperationRequest      = "read-operation-request"
	SchemaReadOperationResult       = "read-operation-result"
	SchemaAgentConsultation         = "agent-consultation"
)
