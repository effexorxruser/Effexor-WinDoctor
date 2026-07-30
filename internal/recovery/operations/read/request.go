package read

import (
	"context"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// StoreVerifier performs read-only Case Store integrity checks.
type StoreVerifier interface {
	Verify(ctx context.Context, caseID string) (casestore.IntegrityReport, error)
}

// Request is the registry execution input: typed envelope plus Case snapshot context.
type Request struct {
	domain.ReadOperationRequest
	Snapshot      casestore.Snapshot
	StoreVerifier StoreVerifier
}
