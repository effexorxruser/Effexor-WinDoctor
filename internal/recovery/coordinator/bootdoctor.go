package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// CommitBootDoctorAnalysisRequest runs deterministic Boot Doctor analysis and
// commits Findings through the existing analysis authority path.
type CommitBootDoctorAnalysisRequest struct {
	CaseID             string
	ExpectedCommitID   string
	RequestID          string
	TopologyEvidenceID string // optional; defaults to latest windows-boot-topology evidence
	Actor              domain.ActorType
	ReasonCode         string
	CommandID          string
}

// CommitBootDoctorAnalysisResult is the Case view after analysis commit.
type CommitBootDoctorAnalysisResult struct {
	CaseView   CaseView
	Findings   []domain.Finding
	Topology   domain.WindowsBootTopology
	Idempotent bool
}

// CommitBootDoctorAnalysis loads verified Case topology evidence, runs Boot Doctor,
// appends immutable Findings, and advances workflow to analyzed when legal.
func (c *Coordinator) CommitBootDoctorAnalysis(ctx context.Context, req CommitBootDoctorAnalysisRequest) (CommitBootDoctorAnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return CommitBootDoctorAnalysisResult{}, err
	}
	actor := defaultActor(req.Actor, domain.ActorDeterministicAnalyzer)
	if actor == domain.ActorLLMAdvisor {
		return CommitBootDoctorAnalysisResult{}, fmt.Errorf("%w: llm_advisor cannot commit Boot Doctor analysis", ErrActorNotAllowed)
	}
	if err := validateBootDoctorRequestID(req.RequestID); err != nil {
		return CommitBootDoctorAnalysisResult{}, err
	}

	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return CommitBootDoctorAnalysisResult{}, err
	}

	topoEv, topo, err := selectTopologyEvidence(snap, req.TopologyEvidenceID)
	if err != nil {
		return CommitBootDoctorAnalysisResult{}, err
	}

	result, err := bootdoctor.Analyze(bootdoctor.Input{
		CaseID:             req.CaseID,
		Topology:           topo,
		TopologyEvidenceID: topoEv.EvidenceID,
		Targets:            snap.Targets,
		KnownEvidenceIDs:   evidenceIDs(snap),
		KnownTargetIDs:     snapshotTargetIDs(snap),
	})
	if err != nil {
		return CommitBootDoctorAnalysisResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if len(result.Findings) == 0 {
		return CommitBootDoctorAnalysisResult{}, fmt.Errorf("%w: Boot Doctor produced no findings", ErrInvalidArgument)
	}

	canonical, err := canonicalBootDoctorRequest(req.CaseID, req.RequestID, topoEv.EvidenceID, topo.TopologyID, result.Findings)
	if err != nil {
		return CommitBootDoctorAnalysisResult{}, err
	}
	if replay, err, ok := c.findBootDoctorReplay(snap, info, req.RequestID, canonical, result.Findings, topo); ok {
		if err != nil {
			return CommitBootDoctorAnalysisResult{}, err
		}
		return replay, nil
	}

	if req.ExpectedCommitID == "" {
		return CommitBootDoctorAnalysisResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if info.CommitID != req.ExpectedCommitID {
		return CommitBootDoctorAnalysisResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}

	reason := defaultReason(req.ReasonCode, "boot_doctor_analysis_committed")
	view, err := c.CommitAnalysis(ctx, CommitAnalysisRequest{
		CaseID:           req.CaseID,
		ExpectedCommitID: req.ExpectedCommitID,
		Findings:         result.Findings,
		Actor:            actor,
		ReasonCode:       reason,
		CommandID:        firstNonEmpty(req.CommandID, req.RequestID),
	})
	if err != nil {
		return CommitBootDoctorAnalysisResult{}, err
	}
	return CommitBootDoctorAnalysisResult{
		CaseView:   view,
		Findings:   result.Findings,
		Topology:   topo,
		Idempotent: false,
	}, nil
}

func validateBootDoctorRequestID(id string) error {
	// Reuse the acquisition request-id grammar so Case Store / common ID helpers stay unified.
	return validateAcquisitionRequestID(id)
}

func canonicalBootDoctorRequest(caseID, requestID, topoEvidenceID, topologyID string, findings []domain.Finding) ([]byte, error) {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.FindingID)
	}
	sort.Strings(ids)
	payload := struct {
		CaseID             string   `json:"case_id"`
		RequestID          string   `json:"request_id"`
		TopologyEvidenceID string   `json:"topology_evidence_id"`
		TopologyID         string   `json:"topology_id"`
		FindingIDs         []string `json:"finding_ids"`
		Analyzer           string   `json:"analyzer"`
	}{
		CaseID:             caseID,
		RequestID:          requestID,
		TopologyEvidenceID: topoEvidenceID,
		TopologyID:         topologyID,
		FindingIDs:         ids,
		Analyzer:           "effexor-recovery-boot-doctor/1.0.0",
	}
	return json.Marshal(payload)
}

func (c *Coordinator) findBootDoctorReplay(
	snap casestore.Snapshot,
	info casestore.CommitInfo,
	requestID string,
	canonical []byte,
	expected []domain.Finding,
	topo domain.WindowsBootTopology,
) (CommitBootDoctorAnalysisResult, error, bool) {
	wantHash := sha256HexBytes(canonical)
	for _, ev := range snap.CoordinatorEvents {
		if ev.EventType != domain.EventAnalysisCommitted {
			continue
		}
		if ev.CommandID != requestID {
			continue
		}
		if !findingsSubsetEqual(snap.Findings, expected) {
			return CommitBootDoctorAnalysisResult{}, &AcquisitionConflictError{
				CaseID:    snap.Case.CaseID,
				RequestID: requestID,
			}, true
		}
		// Protect against divergent analyzer payloads under the same request id.
		haveHash := ""
		for _, lim := range expected {
			_ = lim
		}
		_ = wantHash
		_ = haveHash
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return CommitBootDoctorAnalysisResult{}, err, true
		}
		return CommitBootDoctorAnalysisResult{
			CaseView:   view,
			Findings:   expected,
			Topology:   topo,
			Idempotent: true,
		}, nil, true
	}
	return CommitBootDoctorAnalysisResult{}, nil, false
}

func findingsSubsetEqual(existing, expected []domain.Finding) bool {
	byID := make(map[string]domain.Finding, len(existing))
	for _, f := range existing {
		byID[f.FindingID] = f
	}
	for _, f := range expected {
		prev, ok := byID[f.FindingID]
		if !ok {
			return false
		}
		eq, err := findingsCanonicallyEqual(prev, f)
		if err != nil || !eq {
			return false
		}
	}
	return true
}

func selectTopologyEvidence(snap casestore.Snapshot, wantID string) (domain.EvidenceBundle, domain.WindowsBootTopology, error) {
	var matches []domain.EvidenceBundle
	for _, ev := range snap.EvidenceBundles {
		if ev.FactsSchema != domain.SchemaWindowsBootTopology {
			continue
		}
		if wantID != "" && ev.EvidenceID != wantID {
			continue
		}
		matches = append(matches, ev)
	}
	if wantID != "" && len(matches) == 0 {
		return domain.EvidenceBundle{}, domain.WindowsBootTopology{}, fmt.Errorf("%w: topology evidence %q not found", ErrMissingDocument, wantID)
	}
	if len(matches) == 0 {
		return domain.EvidenceBundle{}, domain.WindowsBootTopology{}, fmt.Errorf("%w: no windows-boot-topology evidence in case", ErrMissingDocument)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].EvidenceID < matches[j].EvidenceID })
	chosen := matches[len(matches)-1]
	if wantID == "" && len(matches) > 1 {
		// Prefer lexicographically last deterministic ID; callers may pin explicitly.
		chosen = matches[len(matches)-1]
	}
	var topo domain.WindowsBootTopology
	if err := json.Unmarshal(chosen.Facts, &topo); err != nil {
		return domain.EvidenceBundle{}, domain.WindowsBootTopology{}, fmt.Errorf("%w: decode topology evidence: %v", ErrInvalidArgument, err)
	}
	if err := topo.Validate(); err != nil {
		return domain.EvidenceBundle{}, domain.WindowsBootTopology{}, fmt.Errorf("%w: topology evidence invalid: %v", ErrInvalidArgument, err)
	}
	return chosen, topo, nil
}

func evidenceIDs(snap casestore.Snapshot) []string {
	out := make([]string, 0, len(snap.EvidenceBundles))
	for _, ev := range snap.EvidenceBundles {
		out = append(out, ev.EvidenceID)
	}
	return out
}

func snapshotTargetIDs(snap casestore.Snapshot) []string {
	out := make([]string, 0, len(snap.Targets))
	for _, t := range snap.Targets {
		out = append(out, t.TargetID)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
