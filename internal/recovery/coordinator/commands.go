package coordinator

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// CreateCaseRequest creates a Case from diagnostic-report 1.3.0 bytes.
type CreateCaseRequest struct {
	DiagnosticReport []byte
	SourceArtifact   *domain.ArtifactRef
	ArtifactProvider casestore.ArtifactProvider
	CommandID        string
	Actor            domain.ActorType
	ReasonCode       string
}

// CommitAnalysisRequest commits Findings and transitions to analyzed.
type CommitAnalysisRequest struct {
	CaseID           string
	ExpectedCommitID string
	Findings         []domain.Finding
	Actor            domain.ActorType
	ReasonCode       string
	CommandID        string
}

// CommitPlanRequest commits a RepairPlan and transitions to plan_proposed.
type CommitPlanRequest struct {
	CaseID           string
	ExpectedCommitID string
	Plan             domain.RepairPlan
	Actor            domain.ActorType
	ReasonCode       string
	CommandID        string
}

// FailCaseRequest transitions a Case to failed.
type FailCaseRequest struct {
	CaseID           string
	ExpectedCommitID string
	Actor            domain.ActorType
	ReasonCode       string
	DetailCode       string
	CommandID        string
}

// CancelCaseRequest transitions a Case to cancelled.
type CancelCaseRequest struct {
	CaseID           string
	ExpectedCommitID string
	Actor            domain.ActorType
	ReasonCode       string
	CommandID        string
}
