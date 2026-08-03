package coordinator

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidArgument indicates a caller-supplied value failed validation.
	ErrInvalidArgument = errors.New("coordinator: invalid argument")

	// ErrIllegalTransition indicates a workflow transition is not permitted.
	ErrIllegalTransition = errors.New("coordinator: illegal transition")

	// ErrCaseRevisionConflict indicates expected commit ID did not match latest.
	ErrCaseRevisionConflict = errors.New("coordinator: case revision conflict")

	// ErrCaseCorrupt indicates Case Store integrity prevents Coordinator progress.
	ErrCaseCorrupt = errors.New("coordinator: case store corrupt")

	// ErrMissingDocument indicates a required document for a transition is absent.
	ErrMissingDocument = errors.New("coordinator: missing required document")

	// ErrActorNotAllowed indicates the actor type may not perform the transition.
	ErrActorNotAllowed = errors.New("coordinator: actor not allowed")

	// ErrCaseAlreadyExists indicates CreateCase found an existing Case head.
	ErrCaseAlreadyExists = errors.New("coordinator: case already exists")

	// ErrCaseBusy indicates the Case Store lock is held and the head did not change.
	ErrCaseBusy = errors.New("coordinator: case busy")

	// ErrLegacyAdoptionRejected indicates AdoptLegacyCase preconditions failed.
	ErrLegacyAdoptionRejected = errors.New("coordinator: legacy adoption rejected")

	// ErrAcquisitionConflict indicates the same request_id was reused with a divergent request.
	ErrAcquisitionConflict = errors.New("coordinator: acquisition request conflict")

	// ErrPlannerRefused indicates the deterministic planner declined to propose a plan.
	ErrPlannerRefused = errors.New("coordinator: planner refused")
)

// AcquisitionConflictError carries divergent acquisition request details.
type AcquisitionConflictError struct {
	CaseID    string
	RequestID string
}

func (e *AcquisitionConflictError) Error() string {
	return fmt.Sprintf("coordinator: case %s acquisition request %s conflicts with existing record", e.CaseID, e.RequestID)
}

func (e *AcquisitionConflictError) Is(target error) bool {
	return target == ErrAcquisitionConflict
}

// PlannerRefusalError carries deterministic planner refusal details.
type PlannerRefusalError struct {
	CaseID  string
	Codes   []string
	Message string
}

func (e *PlannerRefusalError) Error() string {
	return fmt.Sprintf("coordinator: planner refused for case %s: %s", e.CaseID, e.Message)
}

func (e *PlannerRefusalError) Is(target error) bool {
	return target == ErrPlannerRefused
}

// RevisionConflictError carries optimistic concurrency details.
type RevisionConflictError struct {
	CaseID           string
	ExpectedCommitID string
	ActualCommitID   string
}

func (e *RevisionConflictError) Error() string {
	return fmt.Sprintf("coordinator: case %s revision conflict: expected commit %s, actual %s",
		e.CaseID, e.ExpectedCommitID, e.ActualCommitID)
}

func (e *RevisionConflictError) Is(target error) bool {
	return target == ErrCaseRevisionConflict
}

// CaseAlreadyExistsError is returned by CreateCase when the Case already has a head.
type CaseAlreadyExistsError struct {
	CaseID         string
	ExistingCommit string
}

func (e *CaseAlreadyExistsError) Error() string {
	return fmt.Sprintf("coordinator: case %s already exists (commit %s)", e.CaseID, e.ExistingCommit)
}

func (e *CaseAlreadyExistsError) Is(target error) bool {
	return target == ErrCaseAlreadyExists
}

// TransitionError describes an illegal or incomplete transition attempt.
type TransitionError struct {
	CaseID  string
	From    string
	To      string
	Reason  string
	Message string
}

func (e *TransitionError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("coordinator: %s", e.Message)
	}
	return fmt.Sprintf("coordinator: illegal transition %s -> %s for case %s (%s)", e.From, e.To, e.CaseID, e.Reason)
}

func (e *TransitionError) Is(target error) bool {
	switch e.Reason {
	case "missing_findings", "missing_plan":
		return target == ErrMissingDocument || target == ErrIllegalTransition
	case "actor_not_allowed":
		return target == ErrActorNotAllowed || target == ErrIllegalTransition
	default:
		return target == ErrIllegalTransition
	}
}
