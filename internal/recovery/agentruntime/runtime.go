package agentruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	readops "github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/read"
)

// Options bounds the Recovery Agent Runtime loop.
type Options struct {
	MaxRounds        int
	Timeout          time.Duration
	MaxRequestBytes  int
	MaxResponseBytes int
	Now              func() time.Time
}

// Runtime runs a bounded advisory consultation against a Recovery Case.
type Runtime struct {
	Port     CasePort
	Provider RoundProvider
	Registry *readops.Registry
	Options  Options
}

// Request starts or retries an advisory consultation.
type Request struct {
	CaseID           string
	ExpectedCommitID string
	RequestID        string
	Actor            domain.ActorType
}

// Result is the terminal runtime outcome.
type Result struct {
	Status       string
	Consultation *domain.AgentConsultation
	CaseView     *coordinator.CaseView
	Idempotent   bool
	RoundCount   int
	Detail       string
}

// Run executes the Recovery Agent Runtime v2 loop.
func (rt Runtime) Run(ctx context.Context, req Request) (Result, error) {
	if rt.Port == nil {
		return Result{Status: StatusFailed, Detail: "case port required"}, fmt.Errorf("case port required")
	}
	if rt.Provider == nil {
		return Result{Status: StatusFailed, Detail: "provider required"}, fmt.Errorf("provider required")
	}
	if rt.Registry == nil {
		reg, err := readops.NewRegistry()
		if err != nil {
			return Result{Status: StatusFailed, Detail: err.Error()}, err
		}
		rt.Registry = reg
	}
	opts := rt.normalizedOptions()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	view, err := rt.Port.LoadCase(ctx, req.CaseID)
	if err != nil {
		return Result{Status: StatusFailed, Detail: err.Error()}, err
	}
	if existing, ok := findConsultationByRequest(view.Snapshot, req.RequestID); ok {
		return Result{
			Status:       existing.Status,
			Consultation: &existing,
			CaseView:     &view,
			Idempotent:   true,
			RoundCount:   existing.RoundCount,
		}, nil
	}
	if req.ExpectedCommitID != "" && req.ExpectedCommitID != view.CommitInfo.CommitID {
		return Result{Status: StatusFailed, Detail: "stale expected_commit_id"}, fmt.Errorf("%w", coordinator.ErrCaseRevisionConflict)
	}
	if view.State != domain.WorkflowAnalyzed {
		return Result{Status: StatusBlocked, Detail: "case not analyzed"}, fmt.Errorf("case workflow must be analyzed")
	}

	actor := req.Actor
	if actor == "" {
		actor = domain.ActorSystem
	}

	commitID := view.CommitInfo.CommitID
	snap := view.Snapshot
	topoID := topologyIDOf(snap)
	digest := InputDigest(req.CaseID, req.RequestID, commitID, topoID, findingIDsOf(snap))
	consultationID := ConsultationID(req.CaseID, req.RequestID, digest)

	sanitized := BuildSanitizedContext(snap, commitID)
	priorEvidence := filterUploadable(sanitized.EvidenceSummaries)
	priorKeys := map[string]struct{}{}
	priorKeyList := []string{}
	var lastProposal ProviderProposal
	roundCount := 0

	for round := 1; round <= opts.MaxRounds; round++ {
		roundCount = round
		if err := ctx.Err(); err != nil {
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, "context canceled", lastProposal)
		}
		input := RoundInput{
			Context:          sanitized,
			Round:            round,
			PriorEvidence:    priorEvidence,
			PriorRequestKeys: append([]string(nil), priorKeyList...),
		}
		if err := validateSize("round input", input, opts.MaxRequestBytes); err != nil {
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, err.Error(), lastProposal)
		}

		pctx := ctx
		if ProviderTimeout > 0 {
			var cancel context.CancelFunc
			pctx, cancel = context.WithTimeout(ctx, ProviderTimeout)
			defer cancel()
		}
		proposal, err := rt.Provider.Propose(pctx, input)
		if err != nil {
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, "provider error", lastProposal)
		}
		lastProposal = proposal
		if err := validateSize("provider proposal", proposal, opts.MaxResponseBytes); err != nil {
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, err.Error(), proposal)
		}
		if err := ValidateProposal(proposal, snap, round, opts.MaxRounds); err != nil {
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, err.Error(), proposal)
		}

		switch proposal.Status {
		case StatusNeedsMoreEvidence:
			authorized, err := AuthorizeReadRequests(snap, rt.Registry, proposal.ReadRequests, priorKeys, MaxReadRequestsTotal-len(priorKeys))
			if err != nil {
				return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusBlocked, err.Error(), proposal)
			}
			newCommit, added, err := executeAuthorizedReads(ctx, rt.Port, req.CaseID, commitID, req.RequestID, round, actor, authorized)
			if err != nil {
				return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, err.Error(), proposal)
			}
			commitID = newCommit
			reloaded, err := rt.Port.LoadCase(ctx, req.CaseID)
			if err != nil {
				return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, err.Error(), proposal)
			}
			view = reloaded
			snap = view.Snapshot
			sanitized = BuildSanitizedContext(snap, commitID)
			for _, auth := range authorized {
				priorKeys[auth.RequestKey] = struct{}{}
				priorKeyList = append(priorKeyList, auth.RequestKey)
			}
			for _, ev := range added {
				if ev.UploadAllowed {
					priorEvidence = append(priorEvidence, ev)
				}
			}
			continue

		case StatusCompleted, StatusBlocked, StatusFailed:
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, proposal.Status, "", proposal)
		default:
			return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, round, StatusFailed, "invalid status", proposal)
		}
	}
	return rt.persistTerminal(ctx, req, view, consultationID, digest, topoID, commitID, roundCount, StatusFailed, "max rounds exceeded", lastProposal)
}

func (rt Runtime) persistTerminal(
	ctx context.Context,
	req Request,
	view coordinator.CaseView,
	consultationID, digest, topoID, commitID string,
	round int,
	status, detail string,
	proposal ProviderProposal,
) (Result, error) {
	proposal = normalizeProposal(proposal, req.CaseID, round, status, detail)
	opts := rt.normalizedOptions()
	cons := buildConsultation(req, consultationID, digest, topoID, commitID, round, view.Snapshot, proposal, opts.Now())
	committed, err := rt.Port.CommitAgentConsultation(ctx, coordinator.CommitAgentConsultationRequest{
		CaseID:           req.CaseID,
		ExpectedCommitID: commitID,
		RequestID:        req.RequestID,
		Consultation:     cons,
		Actor:            domain.ActorLLMAdvisor,
	})
	if err != nil {
		return Result{Status: status, Detail: detail, RoundCount: round}, err
	}
	cv := committed.CaseView
	c := committed.Consultation
	return Result{
		Status:       c.Status,
		Consultation: &c,
		CaseView:     &cv,
		Idempotent:   committed.Idempotent,
		RoundCount:   round,
		Detail:       detail,
	}, nil
}

func normalizeProposal(proposal ProviderProposal, caseID string, round int, status, detail string) ProviderProposal {
	if proposal.Hypotheses == nil {
		proposal.Hypotheses = []HypothesisDraft{}
	}
	if proposal.ReadRequests == nil {
		proposal.ReadRequests = []ReadRequestDraft{}
	}
	if proposal.NextDiagnosticSteps == nil {
		proposal.NextDiagnosticSteps = []string{}
	}
	if proposal.RetrievedSources == nil {
		proposal.RetrievedSources = []SourceDraft{}
	}
	if proposal.Limitations == nil {
		proposal.Limitations = []string{}
	}
	if detail != "" {
		proposal.Limitations = append([]string{detail}, proposal.Limitations...)
	}
	if len(proposal.Limitations) == 0 {
		proposal.Limitations = []string{"advisory consultation"}
	}
	if proposal.ProviderName == "" {
		proposal.ProviderName = "unknown"
	}
	proposal.Status = status
	proposal.CaseID = caseID
	proposal.SchemaVersion = SchemaVersion
	if proposal.Round == 0 {
		proposal.Round = round
	}
	// Terminal persistence never stores needs_more_evidence.
	if proposal.Status == StatusNeedsMoreEvidence {
		proposal.Status = StatusFailed
	}
	proposal.ReadRequests = []ReadRequestDraft{}
	return proposal
}

func buildConsultation(
	req Request,
	consultationID, digest, topoID, sourceCommitID string,
	round int,
	snap casestore.Snapshot,
	proposal ProviderProposal,
	now time.Time,
) domain.AgentConsultation {
	findingRefs := findingIDsOf(snap)
	evidenceRefs := make([]string, 0, len(snap.EvidenceBundles))
	for _, e := range snap.EvidenceBundles {
		evidenceRefs = append(evidenceRefs, e.EvidenceID)
	}
	sort.Strings(evidenceRefs)
	targetRefs := make([]string, 0, len(snap.Targets))
	for _, t := range snap.Targets {
		targetRefs = append(targetRefs, t.TargetID)
	}
	sort.Strings(targetRefs)

	hyps := make([]domain.AdvisoryHypothesis, 0, len(proposal.Hypotheses))
	for i, h := range proposal.Hypotheses {
		hyps = append(hyps, domain.AdvisoryHypothesis{
			HypothesisID:              HypothesisID(consultationID, i, h.Code),
			Code:                      h.Code,
			Title:                     h.Title,
			Rationale:                 h.Rationale,
			Confidence:                h.Confidence,
			SupportingFindingRefs:     nonNil(h.SupportingFindingRefs),
			SupportingEvidenceRefs:    nonNil(h.SupportingEvidenceRefs),
			ContradictingEvidenceRefs: nonNil(h.ContradictingEvidenceRefs),
			Limitations:               nonNil(h.Limitations),
			Advisory:                  true,
		})
		if len(hyps[i].Limitations) == 0 {
			hyps[i].Limitations = []string{"advisory hypothesis"}
		}
	}
	sources := make([]domain.RetrievedSource, 0, len(proposal.RetrievedSources))
	for _, s := range proposal.RetrievedSources {
		sources = append(sources, domain.RetrievedSource{
			URL:    s.URL,
			Domain: s.Domain,
			Title:  s.Title,
		})
	}
	return domain.AgentConsultation{
		SchemaName:          domain.SchemaAgentConsultation,
		SchemaVersion:       domain.SchemaVersion,
		ConsultationID:      consultationID,
		CaseID:              req.CaseID,
		RequestID:           req.RequestID,
		RuntimeID:           RuntimeID,
		RuntimeVersion:      RuntimeVersion,
		SourceCommitID:      sourceCommitID,
		InputDigest:         digest,
		GeneratedAt:         now.UTC().Format(time.RFC3339),
		Status:              proposal.Status,
		RoundCount:          round,
		TopologyID:          topoID,
		FindingRefs:         findingRefs,
		EvidenceRefs:        evidenceRefs,
		TargetRefs:          targetRefs,
		Hypotheses:          hyps,
		NextDiagnosticSteps: nonNil(proposal.NextDiagnosticSteps),
		RetrievedSources:    sources,
		Limitations:         nonNil(proposal.Limitations),
		ProviderMetadata: domain.ProviderMetadata{
			ProviderName: proposal.ProviderName,
			ModelName:    proposal.ModelName,
		},
		InsufficientEvidence: len(findingRefs) == 0 && len(evidenceRefs) == 0,
	}
}

func findConsultationByRequest(snap casestore.Snapshot, requestID string) (domain.AgentConsultation, bool) {
	for _, c := range snap.AgentConsultations {
		if c.RequestID == requestID {
			return c, true
		}
	}
	return domain.AgentConsultation{}, false
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func filterUploadable(in []SanitizedEvidence) []SanitizedEvidence {
	out := make([]SanitizedEvidence, 0, len(in))
	for _, e := range in {
		if e.UploadAllowed {
			out = append(out, e)
		}
	}
	return out
}

func validateSize(label string, v any, max int) error {
	if max <= 0 {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(raw) > max {
		return fmt.Errorf("%s exceeds size limit", label)
	}
	return nil
}

func (rt Runtime) normalizedOptions() Options {
	opts := rt.Options
	if opts.MaxRounds <= 0 || opts.MaxRounds > MaxRounds {
		opts.MaxRounds = MaxRounds
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = MaxRequestBytes
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = MaxResponseBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}
