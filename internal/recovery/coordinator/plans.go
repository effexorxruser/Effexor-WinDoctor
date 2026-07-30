package coordinator

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// mergePlansImmutable keeps existing RepairPlans immutable by plan_id. A new
// plan_id appends. Reusing the same plan_id with identical canonical JSON is a
// no-op; divergent content is rejected.
func mergePlansImmutable(existing []domain.RepairPlan, incoming domain.RepairPlan) ([]domain.RepairPlan, error) {
	out := append([]domain.RepairPlan(nil), existing...)
	for _, prev := range existing {
		if prev.PlanID != incoming.PlanID {
			continue
		}
		eq, err := plansCanonicallyEqual(prev, incoming)
		if err != nil {
			return nil, err
		}
		if !eq {
			return nil, fmt.Errorf("%w: plan_id %q already exists with divergent content", ErrInvalidArgument, incoming.PlanID)
		}
		return out, nil
	}
	out = append(out, incoming)
	return out, nil
}

func plansCanonicallyEqual(a, b domain.RepairPlan) (bool, error) {
	ba, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ba, bb), nil
}
