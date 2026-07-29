package coordinator

import (
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// allowedPR17Actors may create state transitions in this PR.
var allowedPR17Actors = map[domain.ActorType]struct{}{
	domain.ActorSystem:                {},
	domain.ActorTechnician:            {},
	domain.ActorDeterministicAnalyzer: {},
}

type transitionSpec struct {
	from            domain.WorkflowStateName
	to              domain.WorkflowStateName
	requireFindings bool
	requirePlans    bool
	prohibitPlans   bool
	allowedActors   map[domain.ActorType]struct{}
}

func defaultActors() map[domain.ActorType]struct{} {
	return allowedPR17Actors
}

var pr17Transitions = []transitionSpec{
	{from: domain.WorkflowCreated, to: domain.WorkflowEvidenceCollected, allowedActors: defaultActors()},
	{from: domain.WorkflowEvidenceCollected, to: domain.WorkflowAnalyzed, requireFindings: true, allowedActors: map[domain.ActorType]struct{}{
		domain.ActorDeterministicAnalyzer: {},
		domain.ActorSystem:                {},
	}},
	{from: domain.WorkflowAnalyzed, to: domain.WorkflowAnalyzed, requireFindings: true, allowedActors: map[domain.ActorType]struct{}{
		domain.ActorDeterministicAnalyzer: {},
		domain.ActorSystem:                {},
	}},
	{from: domain.WorkflowAnalyzed, to: domain.WorkflowPlanProposed, requireFindings: true, requirePlans: true, allowedActors: map[domain.ActorType]struct{}{
		domain.ActorSystem:                {},
		domain.ActorTechnician:            {},
		domain.ActorDeterministicAnalyzer: {},
	}},
	{from: domain.WorkflowCreated, to: domain.WorkflowFailed, allowedActors: defaultActors()},
	{from: domain.WorkflowEvidenceCollected, to: domain.WorkflowFailed, allowedActors: defaultActors()},
	{from: domain.WorkflowAnalyzed, to: domain.WorkflowFailed, allowedActors: defaultActors()},
	{from: domain.WorkflowPlanProposed, to: domain.WorkflowFailed, allowedActors: defaultActors()},
	{from: domain.WorkflowCreated, to: domain.WorkflowCancelled, allowedActors: defaultActors()},
	{from: domain.WorkflowEvidenceCollected, to: domain.WorkflowCancelled, allowedActors: defaultActors()},
	{from: domain.WorkflowAnalyzed, to: domain.WorkflowCancelled, allowedActors: defaultActors()},
	{from: domain.WorkflowPlanProposed, to: domain.WorkflowCancelled, allowedActors: defaultActors()},
}

func findTransition(from, to domain.WorkflowStateName) (transitionSpec, bool) {
	for _, t := range pr17Transitions {
		if t.from == from && t.to == to {
			return t, true
		}
	}
	return transitionSpec{}, false
}

func validateTransition(from, to domain.WorkflowStateName, actor domain.ActorType, findings int, plans int) error {
	spec, ok := findTransition(from, to)
	if !ok {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "not_allowed",
			Message: fmt.Sprintf("transition %s -> %s is not implemented in PR #17", from, to),
		}
	}
	if _, ok := spec.allowedActors[actor]; !ok {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "actor_not_allowed",
			Message: fmt.Sprintf("actor %s may not transition %s -> %s", actor, from, to),
		}
	}
	if _, ok := allowedPR17Actors[actor]; !ok {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "actor_not_allowed",
			Message: fmt.Sprintf("actor %s is not permitted in PR #17", actor),
		}
	}
	if spec.requireFindings && findings == 0 {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "missing_findings",
			Message: "transition requires at least one Finding",
		}
	}
	if spec.requirePlans && plans == 0 {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "missing_plan",
			Message: "transition requires at least one RepairPlan",
		}
	}
	if spec.prohibitPlans && plans > 0 {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "prohibited_plan",
			Message: "transition prohibits RepairPlan documents",
		}
	}
	return nil
}
