package coordinator

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// mergeFindingsAppendOnly keeps existing Findings immutable. New Finding IDs are
// appended. Duplicate FindingID with identical canonical JSON is a no-op.
// Duplicate FindingID with divergent content is rejected.
func mergeFindingsAppendOnly(existing, incoming []domain.Finding) ([]domain.Finding, error) {
	byID := make(map[string]domain.Finding, len(existing)+len(incoming))
	out := make([]domain.Finding, 0, len(existing)+len(incoming))
	for _, f := range existing {
		byID[f.FindingID] = f
		out = append(out, f)
	}
	for _, f := range incoming {
		if prev, ok := byID[f.FindingID]; ok {
			eq, err := findingsCanonicallyEqual(prev, f)
			if err != nil {
				return nil, err
			}
			if !eq {
				return nil, fmt.Errorf("%w: finding_id %q already exists with divergent content",
					ErrInvalidArgument, f.FindingID)
			}
			continue
		}
		byID[f.FindingID] = f
		out = append(out, f)
	}
	return out, nil
}

func findingsCanonicallyEqual(a, b domain.Finding) (bool, error) {
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
