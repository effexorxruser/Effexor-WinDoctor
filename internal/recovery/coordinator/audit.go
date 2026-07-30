package coordinator

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
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
	workflowRevision uint64,
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
		WorkflowRevision:      workflowRevision,
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

func stampAuditEvent(snap *casestore.Snapshot, eventID string, refs []string, occurredAt string) {
	for i := range snap.CoordinatorEvents {
		if snap.CoordinatorEvents[i].EventID == eventID {
			snap.CoordinatorEvents[i].ReferencedDocumentIDs = append([]string(nil), refs...)
			snap.CoordinatorEvents[i].OccurredAt = occurredAt
			break
		}
	}
}
