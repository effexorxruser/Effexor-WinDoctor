package agentruntime

import (
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestBuildConsultationPreservesHypothesisSlices(t *testing.T) {
	snap := casestore.Snapshot{
		Case: domain.CaseManifest{CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa"},
		Findings: []domain.Finding{{
			FindingID: "finding-aaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		EvidenceBundles: []domain.EvidenceBundle{{
			EvidenceID: "evidence-aaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		Targets: []domain.Target{{TargetID: "target-fw-0001"}},
	}
	proposal := ProviderProposal{
		Status: StatusCompleted,
		Hypotheses: []HypothesisDraft{{
			Code:                      "test_code",
			Title:                     "title",
			Rationale:                 "rationale text",
			Confidence:                "low",
			SupportingFindingRefs:     []string{"finding-aaaaaaaaaaaaaaaaaaaaaaaa"},
			SupportingEvidenceRefs:    []string{"evidence-aaaaaaaaaaaaaaaaaaaaaaaa"},
			ContradictingEvidenceRefs: []string{},
			Limitations:               []string{"lim"},
		}},
		NextDiagnosticSteps: []string{},
		RetrievedSources:    []SourceDraft{},
		Limitations:         []string{"lim"},
		ProviderName:        "mock",
	}
	cons := buildConsultation(Request{CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa", RequestID: "creq-aaaaaaaaaaaaaaaaaaaaaaaa"},
		"consult-aaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"",
		"commit-aaaaaaaaaaaaaaaaaaaaaaaa",
		1,
		snap,
		proposal,
		time.Unix(0, 0).UTC(),
	)
	if cons.Hypotheses[0].ContradictingEvidenceRefs == nil {
		t.Fatal("contradicting refs nil")
	}
	if err := cons.Hypotheses[0].Validate("hypotheses[0]"); err != nil {
		t.Fatal(err)
	}
}
