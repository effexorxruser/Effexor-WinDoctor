package coordinator

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func (c *Coordinator) newAuditEvent(
	caseID string,
	eventType domain.CoordinatorEventType,
	actor domain.ActorType,
	prev, next domain.WorkflowStateName,
	expectedCommitID string,
	refs []string,
	reasonCode string,
	commandID string,
) (domain.CoordinatorEvent, error) {
	eventID, err := c.newEventID()
	if err != nil {
		return domain.CoordinatorEvent{}, err
	}
	if refs == nil {
		refs = []string{}
	}
	ev := domain.CoordinatorEvent{
		SchemaName:            domain.SchemaCoordinatorEvent,
		SchemaVersion:         domain.SchemaVersion,
		EventID:               eventID,
		CaseID:                caseID,
		EventType:             eventType,
		ActorType:             actor,
		OccurredAt:            c.nowRFC3339(),
		ExpectedCommitID:      expectedCommitID,
		ReferencedDocumentIDs: refs,
		ReasonCode:            reasonCode,
		CommandID:             commandID,
	}
	if prev != "" {
		ev.PreviousState = string(prev)
	}
	if next != "" {
		ev.NextState = string(next)
	}
	return ev, nil
}
