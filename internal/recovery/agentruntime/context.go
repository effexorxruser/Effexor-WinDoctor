package agentruntime

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// SanitizedRecoveryContext is the allowlisted provider-visible Case view.
type SanitizedRecoveryContext struct {
	CaseID            string              `json:"case_id"`
	SchemaVersion     string              `json:"schema_version"`
	RuntimeVersion    string              `json:"runtime_version"`
	WorkflowState     string              `json:"workflow_state"`
	SourceCommitID    string              `json:"source_commit_id"`
	Topology          *SanitizedTopology  `json:"topology,omitempty"`
	Findings          []SanitizedFinding  `json:"findings"`
	Targets           []SanitizedTarget   `json:"targets"`
	EvidenceSummaries []SanitizedEvidence `json:"evidence_summaries"`
	Limitations       []string            `json:"limitations"`
	ExplicitLimits    []string            `json:"explicit_limits"`
}

// SanitizedTopology summarizes Boot topology without secrets.
type SanitizedTopology struct {
	TopologyID string   `json:"topology_id"`
	Blockers   []string `json:"blockers"`
	Roles      []string `json:"roles"`
}

// SanitizedFinding is a deterministic Finding summary.
type SanitizedFinding struct {
	FindingID  string   `json:"finding_id"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Title      string   `json:"title"`
	Codes      []string `json:"codes"`
}

// SanitizedTarget is a minimal target summary.
type SanitizedTarget struct {
	TargetID   string `json:"target_id"`
	TargetType string `json:"target_type"`
	RoleHint   string `json:"role_hint,omitempty"`
}

// SanitizedEvidence is privacy-filtered evidence facts for provider rounds.
type SanitizedEvidence struct {
	EvidenceID     string         `json:"evidence_id"`
	TargetID       string         `json:"target_id"`
	FactsSchema    string         `json:"facts_schema"`
	PrivacyClass   string         `json:"privacy_class"`
	ObservationSrc string         `json:"observation_source"`
	UploadAllowed  bool           `json:"upload_allowed"`
	Facts          map[string]any `json:"facts"`
}

// BuildSanitizedContext constructs an allowlisted context from a verified snapshot.
func BuildSanitizedContext(snap casestore.Snapshot, sourceCommitID string) SanitizedRecoveryContext {
	ctx := SanitizedRecoveryContext{
		CaseID:            snap.Case.CaseID,
		SchemaVersion:     SchemaVersion,
		RuntimeVersion:    RuntimeVersion,
		SourceCommitID:    sourceCommitID,
		Findings:          []SanitizedFinding{},
		Targets:           []SanitizedTarget{},
		EvidenceSummaries: []SanitizedEvidence{},
		Limitations: []string{
			"Provider output is advisory only and never grants repair approval.",
			"Read operations observe Case Store snapshot evidence; they do not perform live Windows reinspection.",
		},
		ExplicitLimits: []string{
			"no_repair_plan",
			"no_mutation",
			"no_approval",
			"no_blocker_clearance",
			"workflow_stays_analyzed",
		},
	}
	if snap.WorkflowState != nil {
		ctx.WorkflowState = string(snap.WorkflowState.State)
	}

	for _, t := range snap.Targets {
		ctx.Targets = append(ctx.Targets, SanitizedTarget{
			TargetID:   t.TargetID,
			TargetType: string(t.TargetType),
		})
	}
	sort.Slice(ctx.Targets, func(i, j int) bool { return ctx.Targets[i].TargetID < ctx.Targets[j].TargetID })

	for _, f := range snap.Findings {
		codes := []string{}
		if code := bootdoctor.FindingCodeOf(f); code != "" {
			codes = append(codes, code)
		}
		ctx.Findings = append(ctx.Findings, SanitizedFinding{
			FindingID:  f.FindingID,
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Title:      f.Title,
			Codes:      codes,
		})
	}
	sort.Slice(ctx.Findings, func(i, j int) bool { return ctx.Findings[i].FindingID < ctx.Findings[j].FindingID })

	for _, e := range snap.EvidenceBundles {
		if e.FactsSchema == "windows-boot-topology" {
			var topo domain.WindowsBootTopology
			if err := json.Unmarshal(e.Facts, &topo); err == nil {
				blockers := append([]string(nil), topo.MutationEligibility.Blockers...)
				sort.Strings(blockers)
				roles := make([]string, 0, len(topo.Candidates))
				for _, c := range topo.Candidates {
					roles = append(roles, string(c.Role)+":"+c.TargetID)
				}
				sort.Strings(roles)
				ctx.Topology = &SanitizedTopology{
					TopologyID: topo.TopologyID,
					Blockers:   blockers,
					Roles:      roles,
				}
			}
		}
		class := privacyClassForFactsSchema(e.FactsSchema)
		facts := sanitizeFacts(decodeFactsMap(e.Facts), class)
		ctx.EvidenceSummaries = append(ctx.EvidenceSummaries, SanitizedEvidence{
			EvidenceID:     e.EvidenceID,
			TargetID:       e.TargetID,
			FactsSchema:    e.FactsSchema,
			PrivacyClass:   class,
			ObservationSrc: "case_snapshot",
			UploadAllowed:  MayUpload(class),
			Facts:          facts,
		})
	}
	sort.Slice(ctx.EvidenceSummaries, func(i, j int) bool {
		return ctx.EvidenceSummaries[i].EvidenceID < ctx.EvidenceSummaries[j].EvidenceID
	})
	return ctx
}

func decodeFactsMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func sanitizeFacts(facts map[string]any, class string) map[string]any {
	policy := PolicyFor(class)
	out := map[string]any{}
	for k, v := range facts {
		lk := strings.ToLower(k)
		if policy.IsForbiddenKey(lk) {
			continue
		}
		if containsSecretValue(v) {
			continue
		}
		if policy.AllowedKeys != nil {
			if _, ok := policy.AllowedKeys[lk]; !ok {
				continue
			}
		}
		out[k] = redactValue(v)
	}
	return out
}
