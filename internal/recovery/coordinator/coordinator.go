package coordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

// Store is the Case Store surface required by the Coordinator.
type Store interface {
	Commit(context.Context, casestore.CommitRequest) (casestore.CommitInfo, error)
	LoadLatest(context.Context, string) (casestore.Snapshot, casestore.CommitInfo, error)
	Verify(context.Context, string) (casestore.IntegrityReport, error)
}

// LegacyImporter converts diagnostic-report JSON into Recovery Domain documents.
type LegacyImporter interface {
	ImportJSON(raw []byte, options legacyreport.Options) (legacyreport.Result, error)
}

// Clock supplies wall time for workflow and audit timestamps.
type Clock interface {
	Now() time.Time
}

// IDSource allocates new typed identifiers.
type IDSource interface {
	NewID(prefix string) (string, error)
}

// Coordinator orchestrates Recovery Case lifecycle without mutation authority.
type Coordinator struct {
	store    Store
	importer LegacyImporter
	clock    Clock
	ids      IDSource
}

// Options configures optional Coordinator dependencies.
type Options struct {
	Clock Clock
	IDs   IDSource
}

// New constructs a Coordinator. store and importer are required.
func New(store Store, importer LegacyImporter, opts Options) (*Coordinator, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidArgument)
	}
	if importer == nil {
		return nil, fmt.Errorf("%w: importer is required", ErrInvalidArgument)
	}
	clock := opts.Clock
	if clock == nil {
		clock = systemClock{}
	}
	ids := opts.IDs
	if ids == nil {
		ids = randomIDSource{}
	}
	return &Coordinator{store: store, importer: importer, clock: clock, ids: ids}, nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// CaseView is the typed Coordinator read model for a Case revision.
type CaseView struct {
	Snapshot   casestore.Snapshot
	CommitInfo casestore.CommitInfo
	State      domain.WorkflowStateName
}

func (c *Coordinator) viewFrom(snap casestore.Snapshot, info casestore.CommitInfo) (CaseView, error) {
	state := domain.WorkflowStateName("")
	if snap.WorkflowState != nil {
		state = snap.WorkflowState.State
	}
	return CaseView{Snapshot: snap, CommitInfo: info, State: state}, nil
}

func (c *Coordinator) nowRFC3339() string {
	return c.clock.Now().UTC().Format(time.RFC3339)
}

func isIntegrityFailure(err error) bool {
	var ie *casestore.IntegrityError
	return errors.Is(err, casestore.ErrIntegrity) || errors.As(err, &ie)
}
