package domain_test

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"testing"
)

func TestAgentConsultationHypothesisEmptySlices(t *testing.T) {
	h := domain.AdvisoryHypothesis{
		HypothesisID:              "hyp-aaaaaaaaaaaaaaaaaaaaaaaa",
		Code:                      "test_code",
		Title:                     "t",
		Rationale:                 "r",
		Confidence:                "low",
		SupportingFindingRefs:     []string{},
		SupportingEvidenceRefs:    []string{},
		ContradictingEvidenceRefs: []string{},
		Limitations:               []string{"x"},
		Advisory:                  true,
	}
	if err := h.Validate("hypotheses[0]"); err != nil {
		t.Fatal(err)
	}
}
