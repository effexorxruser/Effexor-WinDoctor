package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	readops "github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/read"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/targetresolver"
)

// ExecuteReadOperationRequest runs a typed read-only operation and may append
// Evidence plus an EvidenceAcquisitionRecord without changing workflow state.
type ExecuteReadOperationRequest struct {
	CaseID           string
	ExpectedCommitID string
	RequestID        string
	OperationID      string
	OperationVersion string
	TargetID         string
	Parameters       json.RawMessage
	Actor            domain.ActorType
}

// ExecuteReadOperationResult is the committed Case view plus observation result.
type ExecuteReadOperationResult struct {
	CaseView    CaseView
	Acquisition domain.EvidenceAcquisitionRecord
	Result      domain.ReadOperationResult
	Evidence    domain.EvidenceBundle
	Idempotent  bool
}

// ResolveWindowsBootTopologyRequest runs the target resolver and may append
// topology Evidence plus an EvidenceAcquisitionRecord.
type ResolveWindowsBootTopologyRequest struct {
	CaseID           string
	ExpectedCommitID string
	RequestID        string
	Selection        *targetresolver.TechnicianSelection
	Actor            domain.ActorType
}

// ResolveWindowsBootTopologyResult is the committed Case view plus topology.
type ResolveWindowsBootTopologyResult struct {
	CaseView    CaseView
	Acquisition domain.EvidenceAcquisitionRecord
	Topology    domain.WindowsBootTopology
	Evidence    domain.EvidenceBundle
	Idempotent  bool
}

// ExecuteReadOperation observes Case evidence (or store integrity) and appends
// acquisition provenance when new evidence is produced.
func (c *Coordinator) ExecuteReadOperation(ctx context.Context, req ExecuteReadOperationRequest) (ExecuteReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return ExecuteReadOperationResult{}, err
	}
	actor, err := requireAcquisitionActor(req.Actor)
	if err != nil {
		return ExecuteReadOperationResult{}, err
	}
	if err := validateAcquisitionRequestID(req.RequestID); err != nil {
		return ExecuteReadOperationResult{}, err
	}
	if req.OperationID == "" || req.OperationVersion == "" || req.TargetID == "" {
		return ExecuteReadOperationResult{}, fmt.Errorf("%w: operation_id, operation_version, and target_id are required", ErrInvalidArgument)
	}
	params := req.Parameters
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}

	canonicalReq, err := canonicalReadAcquisitionRequest(req.CaseID, req.OperationID, req.OperationVersion, req.TargetID, params, nil)
	if err != nil {
		return ExecuteReadOperationResult{}, err
	}

	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return ExecuteReadOperationResult{}, err
	}
	if err := requireEvidenceCollected(snap, req.CaseID); err != nil {
		return ExecuteReadOperationResult{}, err
	}
	if existing, ok := findAcquisition(snap, req.RequestID); ok {
		if existing.ParametersSHA256 != sha256Hex(canonicalReq) {
			return ExecuteReadOperationResult{}, &AcquisitionConflictError{
				CaseID:    req.CaseID,
				RequestID: req.RequestID,
			}
		}
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return ExecuteReadOperationResult{}, err
		}
		ev, ok := evidenceByID(snap, existing.AddedEvidenceIDs)
		if !ok {
			return ExecuteReadOperationResult{}, fmt.Errorf("%w: acquisition evidence missing", ErrMissingDocument)
		}
		var result domain.ReadOperationResult
		if err := json.Unmarshal(ev.Facts, &result); err != nil {
			return ExecuteReadOperationResult{}, fmt.Errorf("%w: decode stored result: %v", ErrInvalidArgument, err)
		}
		return ExecuteReadOperationResult{
			CaseView:    view,
			Acquisition: existing,
			Result:      result,
			Evidence:    ev,
			Idempotent:  true,
		}, nil
	}
	if req.ExpectedCommitID == "" {
		return ExecuteReadOperationResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if info.CommitID != req.ExpectedCommitID {
		return ExecuteReadOperationResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}

	readReqID := derivedReadRequestID(req.RequestID)
	opReq := domain.ReadOperationRequest{
		SchemaName:       domain.SchemaReadOperationRequest,
		SchemaVersion:    domain.SchemaVersion,
		RequestID:        readReqID,
		CaseID:           req.CaseID,
		OperationID:      req.OperationID,
		OperationVersion: req.OperationVersion,
		TargetID:         req.TargetID,
		Parameters:       params,
	}
	opRes, err := c.readOps.Execute(ctx, readops.Request{
		ReadOperationRequest: opReq,
		Snapshot:             snap,
		StoreVerifier:        c.store,
	})
	if err != nil {
		return ExecuteReadOperationResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	// Stamp observed_at with coordinator clock for acquisition-time consistency.
	result := opRes.Read()
	result.ObservedAt = c.monotonicNow(&snap)
	if err := result.Validate(); err != nil {
		return ExecuteReadOperationResult{}, fmt.Errorf("%w: result: %v", ErrInvalidArgument, err)
	}

	bundle, err := readops.EvidenceFromResult(result, "1.0.0")
	if err != nil {
		return ExecuteReadOperationResult{}, fmt.Errorf("%w: evidence: %v", ErrInvalidArgument, err)
	}

	acqID, err := c.ids.NewID("acq")
	if err != nil {
		return ExecuteReadOperationResult{}, err
	}
	inputIDs := append([]string(nil), result.SourceEvidenceIDs...)
	sort.Strings(inputIDs)
	acq := domain.EvidenceAcquisitionRecord{
		SchemaName:       domain.SchemaEvidenceAcquisitionRecord,
		SchemaVersion:    domain.SchemaVersion,
		AcquisitionID:    acqID,
		CaseID:           req.CaseID,
		RequestID:        req.RequestID,
		SourceCommitID:   info.CommitID,
		ProducerType:     domain.ProducerReadOperation,
		ProducerID:       "effexor-recovery-read-operation",
		ProducerVersion:  "1.0.0",
		ActorType:        actor,
		AcquiredAt:       result.ObservedAt,
		TargetIDs:        []string{req.TargetID},
		InputEvidenceIDs: inputIDs,
		AddedTargetIDs:   []string{},
		AddedEvidenceIDs: []string{bundle.EvidenceID},
		ParametersSHA256: sha256Hex(canonicalReq),
		ResultSHA256:     sha256Hex(mustJSON(result)),
		Limitations:      append([]string(nil), result.Limitations...),
	}
	if acq.Limitations == nil {
		acq.Limitations = []string{}
	}

	next, err := appendAcquisition(snap, []domain.Target{}, []domain.EvidenceBundle{bundle}, acq)
	if err != nil {
		return ExecuteReadOperationResult{}, err
	}
	view, err := c.commitSnapshot(ctx, next, info.CommitID)
	if err != nil {
		return ExecuteReadOperationResult{}, err
	}
	return ExecuteReadOperationResult{
		CaseView:    view,
		Acquisition: acq,
		Result:      result,
		Evidence:    bundle,
	}, nil
}

// ResolveWindowsBootTopology builds advisory topology evidence and appends it
// with acquisition provenance when new.
func (c *Coordinator) ResolveWindowsBootTopology(ctx context.Context, req ResolveWindowsBootTopologyRequest) (ResolveWindowsBootTopologyResult, error) {
	if err := ctx.Err(); err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	actor, err := requireAcquisitionActor(req.Actor)
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	if err := validateAcquisitionRequestID(req.RequestID); err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}

	canonicalReq, err := canonicalTopologyAcquisitionRequest(req.CaseID, req.Selection)
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}

	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	if err := requireEvidenceCollected(snap, req.CaseID); err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	if existing, ok := findAcquisition(snap, req.RequestID); ok {
		if existing.ParametersSHA256 != sha256Hex(canonicalReq) {
			return ResolveWindowsBootTopologyResult{}, &AcquisitionConflictError{
				CaseID:    req.CaseID,
				RequestID: req.RequestID,
			}
		}
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return ResolveWindowsBootTopologyResult{}, err
		}
		ev, ok := evidenceByID(snap, existing.AddedEvidenceIDs)
		if !ok {
			return ResolveWindowsBootTopologyResult{}, fmt.Errorf("%w: acquisition evidence missing", ErrMissingDocument)
		}
		var topo domain.WindowsBootTopology
		if err := json.Unmarshal(ev.Facts, &topo); err != nil {
			return ResolveWindowsBootTopologyResult{}, fmt.Errorf("%w: decode stored topology: %v", ErrInvalidArgument, err)
		}
		return ResolveWindowsBootTopologyResult{
			CaseView:    view,
			Acquisition: existing,
			Topology:    topo,
			Evidence:    ev,
			Idempotent:  true,
		}, nil
	}
	if req.ExpectedCommitID == "" {
		return ResolveWindowsBootTopologyResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if info.CommitID != req.ExpectedCommitID {
		return ResolveWindowsBootTopologyResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}

	nowRaw := c.monotonicNow(&snap)
	now, err := time.Parse(time.RFC3339, nowRaw)
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, fmt.Errorf("%w: acquired_at: %v", ErrInvalidArgument, err)
	}
	resolved, err := targetresolver.Resolve(ctx, targetresolver.Request{
		Snapshot:  snap,
		CommitID:  info.CommitID,
		Selection: req.Selection,
		Now:       now.UTC(),
	})
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	acqID, err := c.ids.NewID("acq")
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	inputIDs := inputEvidenceIDs(snap)
	producerType := domain.ProducerTargetResolver
	if req.Selection != nil {
		producerType = domain.ProducerTechnicianSelection
	}
	acq := domain.EvidenceAcquisitionRecord{
		SchemaName:       domain.SchemaEvidenceAcquisitionRecord,
		SchemaVersion:    domain.SchemaVersion,
		AcquisitionID:    acqID,
		CaseID:           req.CaseID,
		RequestID:        req.RequestID,
		SourceCommitID:   info.CommitID,
		ProducerType:     producerType,
		ProducerID:       "effexor-recovery-target-resolver",
		ProducerVersion:  "1.0.0",
		ActorType:        actor,
		AcquiredAt:       resolved.Topology.GeneratedAt,
		TargetIDs:        []string{resolved.Evidence.TargetID},
		InputEvidenceIDs: inputIDs,
		AddedTargetIDs:   []string{},
		AddedEvidenceIDs: []string{resolved.Evidence.EvidenceID},
		ParametersSHA256: sha256Hex(canonicalReq),
		ResultSHA256:     sha256Hex(mustJSON(resolved.Topology)),
		Limitations:      append([]string(nil), resolved.Topology.Limitations...),
	}
	if acq.Limitations == nil {
		acq.Limitations = []string{}
	}

	next, err := appendAcquisition(snap, nil, []domain.EvidenceBundle{resolved.Evidence}, acq)
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	view, err := c.commitSnapshot(ctx, next, info.CommitID)
	if err != nil {
		return ResolveWindowsBootTopologyResult{}, err
	}
	return ResolveWindowsBootTopologyResult{
		CaseView:    view,
		Acquisition: acq,
		Topology:    resolved.Topology,
		Evidence:    resolved.Evidence,
	}, nil
}

func requireEvidenceCollected(snap casestore.Snapshot, caseID string) error {
	state := currentState(snap)
	if state != domain.WorkflowEvidenceCollected {
		return &TransitionError{
			CaseID:  caseID,
			From:    string(state),
			To:      string(domain.WorkflowEvidenceCollected),
			Reason:  "acquisition_not_allowed",
			Message: fmt.Sprintf("PR #18 read/topology acquisition requires workflow state evidence_collected (got %s)", state),
		}
	}
	return nil
}

func requireAcquisitionActor(actor domain.ActorType) (domain.ActorType, error) {
	actor = defaultActor(actor, domain.ActorSystem)
	switch actor {
	case domain.ActorSystem, domain.ActorTechnician:
		return actor, nil
	default:
		return "", fmt.Errorf("%w: actor_type %q", ErrActorNotAllowed, actor)
	}
}

func validateAcquisitionRequestID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidArgument)
	}
	matched := len(id) == len("acqreq-")+24
	if matched {
		for _, r := range id[len("acqreq-"):] {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				matched = false
				break
			}
		}
		if id[:len("acqreq-")] != "acqreq-" {
			matched = false
		}
	}
	if !matched {
		return fmt.Errorf("%w: request_id must match acqreq-<24 lowercase hex>", ErrInvalidArgument)
	}
	return nil
}

func findAcquisition(snap casestore.Snapshot, requestID string) (domain.EvidenceAcquisitionRecord, bool) {
	for _, acq := range snap.EvidenceAcquisitions {
		if acq.RequestID == requestID {
			return acq, true
		}
	}
	return domain.EvidenceAcquisitionRecord{}, false
}

func evidenceByID(snap casestore.Snapshot, ids []string) (domain.EvidenceBundle, bool) {
	want := map[string]struct{}{}
	for _, id := range ids {
		want[id] = struct{}{}
	}
	for _, e := range snap.EvidenceBundles {
		if _, ok := want[e.EvidenceID]; ok {
			return e, true
		}
	}
	return domain.EvidenceBundle{}, false
}

func appendAcquisition(
	snap casestore.Snapshot,
	addedTargets []domain.Target,
	addedEvidence []domain.EvidenceBundle,
	acq domain.EvidenceAcquisitionRecord,
) (casestore.Snapshot, error) {
	next := copySnapshot(snap)
	mergedTargets, err := mergeTargetsAppendOnly(next.Targets, addedTargets)
	if err != nil {
		return casestore.Snapshot{}, err
	}
	next.Targets = mergedTargets
	next.Case.TargetIDs = targetIDs(mergedTargets)

	mergedEvidence, err := mergeEvidenceAppendOnly(next.EvidenceBundles, addedEvidence)
	if err != nil {
		return casestore.Snapshot{}, err
	}
	next.EvidenceBundles = mergedEvidence

	for _, existing := range next.EvidenceAcquisitions {
		if existing.AcquisitionID == acq.AcquisitionID {
			return casestore.Snapshot{}, fmt.Errorf("%w: acquisition_id already exists", ErrInvalidArgument)
		}
		if existing.RequestID == acq.RequestID {
			return casestore.Snapshot{}, fmt.Errorf("%w: request_id already exists", ErrInvalidArgument)
		}
	}
	next.EvidenceAcquisitions = append(next.EvidenceAcquisitions, acq)
	if err := next.Validate(); err != nil {
		return casestore.Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return next, nil
}

func mergeTargetsAppendOnly(existing, incoming []domain.Target) ([]domain.Target, error) {
	out := append([]domain.Target(nil), existing...)
	index := map[string]int{}
	for i, t := range out {
		index[t.TargetID] = i
	}
	for _, t := range incoming {
		if i, ok := index[t.TargetID]; ok {
			prev, err := json.Marshal(out[i])
			if err != nil {
				return nil, err
			}
			next, err := json.Marshal(t)
			if err != nil {
				return nil, err
			}
			if string(prev) != string(next) {
				return nil, fmt.Errorf("%w: target %s content conflict", ErrInvalidArgument, t.TargetID)
			}
			continue
		}
		out = append(out, t)
		index[t.TargetID] = len(out) - 1
	}
	return out, nil
}

func mergeEvidenceAppendOnly(existing, incoming []domain.EvidenceBundle) ([]domain.EvidenceBundle, error) {
	out := append([]domain.EvidenceBundle(nil), existing...)
	index := map[string]int{}
	for i, e := range out {
		index[e.EvidenceID] = i
	}
	for _, e := range incoming {
		if i, ok := index[e.EvidenceID]; ok {
			prev, err := json.Marshal(out[i])
			if err != nil {
				return nil, err
			}
			next, err := json.Marshal(e)
			if err != nil {
				return nil, err
			}
			if string(prev) != string(next) {
				return nil, fmt.Errorf("%w: evidence %s content conflict", ErrInvalidArgument, e.EvidenceID)
			}
			continue
		}
		out = append(out, e)
		index[e.EvidenceID] = len(out) - 1
	}
	return out, nil
}

func targetIDs(targets []domain.Target) []string {
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		ids = append(ids, t.TargetID)
	}
	sort.Strings(ids)
	return ids
}

func inputEvidenceIDs(snap casestore.Snapshot) []string {
	ids := make([]string, 0, len(snap.EvidenceBundles))
	for _, e := range snap.EvidenceBundles {
		ids = append(ids, e.EvidenceID)
	}
	sort.Strings(ids)
	return ids
}

func canonicalReadAcquisitionRequest(caseID, opID, opVer, targetID string, params json.RawMessage, selection *targetresolver.TechnicianSelection) ([]byte, error) {
	type payload struct {
		Kind             string                              `json:"kind"`
		CaseID           string                              `json:"case_id"`
		OperationID      string                              `json:"operation_id"`
		OperationVersion string                              `json:"operation_version"`
		TargetID         string                              `json:"target_id"`
		Parameters       json.RawMessage                     `json:"parameters"`
		Selection        *targetresolver.TechnicianSelection `json:"selection,omitempty"`
	}
	return json.Marshal(payload{
		Kind:             "read_operation",
		CaseID:           caseID,
		OperationID:      opID,
		OperationVersion: opVer,
		TargetID:         targetID,
		Parameters:       params,
		Selection:        selection,
	})
}

func canonicalTopologyAcquisitionRequest(caseID string, selection *targetresolver.TechnicianSelection) ([]byte, error) {
	type payload struct {
		Kind      string                              `json:"kind"`
		CaseID    string                              `json:"case_id"`
		Selection *targetresolver.TechnicianSelection `json:"selection"`
	}
	return json.Marshal(payload{Kind: "windows_boot_topology", CaseID: caseID, Selection: selection})
}

func derivedReadRequestID(acqRequestID string) string {
	sum := sha256.Sum256([]byte("readreq|" + acqRequestID))
	return "readreq-" + hex.EncodeToString(sum[:12])
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
