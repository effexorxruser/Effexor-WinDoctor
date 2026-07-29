package coordinator

import (
	"context"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// LoadCase verifies Case Store integrity then returns the latest committed view.
func (c *Coordinator) LoadCase(ctx context.Context, caseID string) (CaseView, error) {
	if caseID == "" {
		return CaseView{}, fmt.Errorf("%w: case_id is required", ErrInvalidArgument)
	}
	report, err := c.store.Verify(ctx, caseID)
	if err != nil {
		if isIntegrityFailure(err) {
			return CaseView{}, fmt.Errorf("%w: %v", ErrCaseCorrupt, err)
		}
		return CaseView{}, err
	}
	if report.Status == casestore.IntegrityCorrupt {
		return CaseView{}, fmt.Errorf("%w: verify status corrupt for case %s", ErrCaseCorrupt, caseID)
	}

	snap, info, err := c.store.LoadLatest(ctx, caseID)
	if err != nil {
		if isIntegrityFailure(err) {
			return CaseView{}, fmt.Errorf("%w: %v", ErrCaseCorrupt, err)
		}
		return CaseView{}, err
	}

	// case_loaded is a read-side audit type; it is not persisted in PR #17 to
	// avoid mutating Case state on every load. Callers may observe EventCaseLoaded
	// in contracts for future append-only load audits.
	_ = domain.EventCaseLoaded
	return c.viewFrom(snap, info)
}
