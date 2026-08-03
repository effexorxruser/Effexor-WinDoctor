package agentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// CasePort is the Coordinator surface used by the runtime.
type CasePort interface {
	LoadCase(ctx context.Context, caseID string) (coordinator.CaseView, error)
	ExecuteReadOperation(ctx context.Context, req coordinator.ExecuteReadOperationRequest) (coordinator.ExecuteReadOperationResult, error)
	CommitAgentConsultation(ctx context.Context, req coordinator.CommitAgentConsultationRequest) (coordinator.CommitAgentConsultationResult, error)
}

func acquisitionRequestID(consultationRequestID string, round int, requestKey string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("acq|%s|%d|%s", consultationRequestID, round, requestKey)))
	return "acqreq-" + hex.EncodeToString(sum[:12])
}

func executeAuthorizedReads(
	ctx context.Context,
	port CasePort,
	caseID string,
	commitID string,
	consultationRequestID string,
	round int,
	actor domain.ActorType,
	reqs []AuthorizedReadRequest,
) (string, []SanitizedEvidence, error) {
	currentCommit := commitID
	added := []SanitizedEvidence{}
	for _, req := range reqs {
		res, err := func() (coordinator.ExecuteReadOperationResult, error) {
			opCtx := ctx
			var cancel context.CancelFunc
			if OperationTimeout > 0 {
				opCtx, cancel = context.WithTimeout(ctx, OperationTimeout)
				defer cancel()
			}
			return port.ExecuteReadOperation(opCtx, coordinator.ExecuteReadOperationRequest{
				CaseID:           caseID,
				ExpectedCommitID: currentCommit,
				RequestID:        acquisitionRequestID(consultationRequestID, round, req.RequestKey),
				OperationID:      req.OperationID,
				OperationVersion: req.OperationVersion,
				TargetID:         req.TargetID,
				Parameters:       req.Parameters,
				Actor:            actor,
			})
		}()
		if err != nil {
			return currentCommit, added, err
		}
		currentCommit = res.CaseView.CommitInfo.CommitID
		class := privacyClassForFactsSchema(res.Evidence.FactsSchema)
		facts := sanitizeFacts(decodeFactsMap(res.Evidence.Facts), class)
		added = append(added, SanitizedEvidence{
			EvidenceID:     res.Evidence.EvidenceID,
			TargetID:       res.Evidence.TargetID,
			FactsSchema:    res.Evidence.FactsSchema,
			PrivacyClass:   class,
			ObservationSrc: "case_snapshot",
			UploadAllowed:  MayUpload(class),
			Facts:          facts,
		})
	}
	return currentCommit, added, nil
}
