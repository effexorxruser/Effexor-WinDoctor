package domain_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func fixturesRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "recovery"))
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{fixturesRoot(t)}, parts...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func TestValidFixturesRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file string
		run  func([]byte) error
	}{
		{"case-manifest.json", func(raw []byte) error {
			var v domain.CaseManifest
			if err := domain.DecodeAndValidateJSON(raw, &v); err != nil {
				return err
			}
			out, err := json.Marshal(v)
			if err != nil {
				return err
			}
			var again domain.CaseManifest
			return domain.DecodeAndValidateJSON(out, &again)
		}},
		{"target.json", func(raw []byte) error {
			var v domain.Target
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"evidence-bundle.json", func(raw []byte) error {
			var v domain.EvidenceBundle
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"finding.json", func(raw []byte) error {
			var v domain.Finding
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"finding-insufficient.json", func(raw []byte) error {
			var v domain.Finding
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan-ordered-deps.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"operation-descriptor.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"execution-event.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-event-started.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-event-failed.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"verification-report.json", func(raw []byte) error {
			var v domain.VerificationReport
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"policy-evaluation.json", func(raw []byte) error {
			var v domain.PolicyEvaluation
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-approval.json", func(raw []byte) error {
			var v domain.RepairApproval
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()
			if err := test.run(readFixture(t, "valid", test.file)); err != nil {
				t.Fatalf("valid fixture failed: %v", err)
			}
		})
	}
}

func TestInvalidFixturesRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file string
		run  func([]byte) error
	}{
		{"case-manifest-bad-enum.json", func(raw []byte) error {
			var v domain.CaseManifest
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"case-manifest-bad-timestamp.json", func(raw []byte) error {
			var v domain.CaseManifest
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"case-manifest-unknown-field.json", func(raw []byte) error {
			var v domain.CaseManifest
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"target-unknown-field.json", func(raw []byte) error {
			var v domain.Target
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"evidence-unsafe-relative-path.json", func(raw []byte) error {
			var v domain.EvidenceBundle
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"evidence-bad-sha256.json", func(raw []byte) error {
			var v domain.EvidenceBundle
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"finding-missing-evidence.json", func(raw []byte) error {
			var v domain.Finding
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"operation-raw-command.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-readonly-mutation.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-readonly-backup.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-nonreadonly-mutation-none.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-controlled-no-approval.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-destructive-no-approval.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-irreversible-no-approval.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-irreversible-rollback.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"operation-reversible-unavailable-rollback.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"repair-plan-bad-dependency.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan-self-dependency.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan-forward-dependency.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan-duplicate-dependency.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan-cycle.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-bad-enum.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-started-with-completed-at.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-started-with-exit-code.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-terminal-missing-completed-at.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-succeeded-with-error.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-failed-missing-error.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"verification-bad-evidence-ref.json", func(raw []byte) error {
			var v domain.VerificationReport
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()
			if err := test.run(readFixture(t, "invalid", test.file)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestValidatePR17CoordinatorEventSemanticsRejectsDisallowedActors(t *testing.T) {
	t.Parallel()
	actors := []domain.ActorType{
		domain.ActorLLMAdvisor,
		domain.ActorPolicy,
		domain.ActorExecutor,
		domain.ActorVerifier,
	}
	for _, actor := range actors {
		actor := actor
		t.Run(string(actor), func(t *testing.T) {
			t.Parallel()
			ev := domain.CoordinatorEvent{
				SchemaName:            domain.SchemaCoordinatorEvent,
				SchemaVersion:         domain.SchemaVersion,
				EventID:               "cevt-111111111111111111111111",
				CaseID:                "case-aaaaaaaaaaaaaaaaaaaaaaaa",
				EventType:             domain.EventAnalysisCommitted,
				ActorType:             actor,
				OccurredAt:            "2026-07-27T12:05:00Z",
				PreviousState:         string(domain.WorkflowEvidenceCollected),
				NextState:             string(domain.WorkflowAnalyzed),
				ExpectedCommitID:      "commit-111111111111111111111111",
				WorkflowRevision:      2,
				ReferencedDocumentIDs: []string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
				ReasonCode:            "analysis_committed",
			}
			if err := domain.ValidatePR17CoordinatorEventSemantics(ev); err == nil {
				t.Fatal("expected disallowed actor rejection")
			}
		})
	}
}

func TestIsStateChangingCoordinatorEventTypeConcurrent(t *testing.T) {
	t.Parallel()
	types := []domain.CoordinatorEventType{
		domain.EventCaseCreated,
		domain.EventAnalysisCommitted,
		domain.EventPlanCommitted,
		domain.EventPolicyEvaluated,
		domain.EventApprovalCommitted,
		domain.EventCaseFailed,
		domain.EventCaseCancelled,
		domain.EventLegacyCaseAdopted,
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		for _, eventType := range types {
			wg.Add(1)
			go func(eventType domain.CoordinatorEventType) {
				defer wg.Done()
				_ = domain.IsStateChangingCoordinatorEventType(eventType)
			}(eventType)
		}
	}
	wg.Wait()
}

func TestValidatePR17CoordinatorEventSemanticsExpectedCommitPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ev      domain.CoordinatorEvent
		wantErr bool
	}{
		{
			name: "case_created forbids expected_commit",
			ev: domain.CoordinatorEvent{
				SchemaName:            domain.SchemaCoordinatorEvent,
				SchemaVersion:         domain.SchemaVersion,
				EventID:               "cevt-111111111111111111111111",
				CaseID:                "case-aaaaaaaaaaaaaaaaaaaaaaaa",
				EventType:             domain.EventCaseCreated,
				ActorType:             domain.ActorSystem,
				OccurredAt:            "2026-07-27T12:05:00Z",
				PreviousState:         string(domain.WorkflowCreated),
				NextState:             string(domain.WorkflowEvidenceCollected),
				ExpectedCommitID:      "commit-111111111111111111111111",
				WorkflowRevision:      1,
				ReferencedDocumentIDs: []string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
				ReasonCode:            "legacy_import_committed",
			},
			wantErr: true,
		},
		{
			name: "legacy adoption requires expected_commit",
			ev: domain.CoordinatorEvent{
				SchemaName:            domain.SchemaCoordinatorEvent,
				SchemaVersion:         domain.SchemaVersion,
				EventID:               "cevt-111111111111111111111111",
				CaseID:                "case-aaaaaaaaaaaaaaaaaaaaaaaa",
				EventType:             domain.EventLegacyCaseAdopted,
				ActorType:             domain.ActorSystem,
				OccurredAt:            "2026-07-27T12:05:00Z",
				NextState:             string(domain.WorkflowEvidenceCollected),
				WorkflowRevision:      1,
				ReferencedDocumentIDs: []string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
				ReasonCode:            "legacy_case_adopted",
			},
			wantErr: true,
		},
		{
			name: "revision greater than one requires expected_commit",
			ev: domain.CoordinatorEvent{
				SchemaName:            domain.SchemaCoordinatorEvent,
				SchemaVersion:         domain.SchemaVersion,
				EventID:               "cevt-111111111111111111111111",
				CaseID:                "case-aaaaaaaaaaaaaaaaaaaaaaaa",
				EventType:             domain.EventAnalysisCommitted,
				ActorType:             domain.ActorSystem,
				OccurredAt:            "2026-07-27T12:05:00Z",
				PreviousState:         string(domain.WorkflowEvidenceCollected),
				NextState:             string(domain.WorkflowAnalyzed),
				WorkflowRevision:      2,
				ReferencedDocumentIDs: []string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
				ReasonCode:            "analysis_committed",
			},
			wantErr: true,
		},
		{
			name: "analysis with expected_commit valid",
			ev: domain.CoordinatorEvent{
				SchemaName:            domain.SchemaCoordinatorEvent,
				SchemaVersion:         domain.SchemaVersion,
				EventID:               "cevt-111111111111111111111111",
				CaseID:                "case-aaaaaaaaaaaaaaaaaaaaaaaa",
				EventType:             domain.EventAnalysisCommitted,
				ActorType:             domain.ActorDeterministicAnalyzer,
				OccurredAt:            "2026-07-27T12:05:00Z",
				PreviousState:         string(domain.WorkflowEvidenceCollected),
				NextState:             string(domain.WorkflowAnalyzed),
				ExpectedCommitID:      "commit-111111111111111111111111",
				WorkflowRevision:      2,
				ReferencedDocumentIDs: []string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
				ReasonCode:            "analysis_committed",
			},
			wantErr: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := domain.ValidatePR17CoordinatorEventSemantics(test.ev)
			if test.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCrossReferenceValidation(t *testing.T) {
	t.Parallel()

	t.Run("finding", func(t *testing.T) {
		t.Parallel()
		var finding domain.Finding
		if err := domain.DecodeAndValidateJSON(readFixture(t, "valid", "finding.json"), &finding); err != nil {
			t.Fatalf("decode finding: %v", err)
		}
		good := domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-disk-nvme0n1"},
			[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
			nil, nil, nil,
		)
		if err := finding.ValidateFindingRefs(good); err != nil {
			t.Fatalf("ValidateFindingRefs() error = %v", err)
		}
		missingEvidence := domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-disk-nvme0n1"},
			[]string{"evidence-000000000000000000000000"},
			nil, nil, nil,
		)
		if err := finding.ValidateFindingRefs(missingEvidence); err == nil {
			t.Fatal("expected missing evidence_ref failure")
		}
		missingCase := domain.NewCrossRefs(
			[]string{"case-000000000000000000000000"},
			[]string{"target-disk-nvme0n1"},
			[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
			nil, nil, nil,
		)
		if err := finding.ValidateFindingRefs(missingCase); err == nil {
			t.Fatal("expected missing case_id failure")
		}
		missingTarget := domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-000000000000000000000000"},
			[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
			nil, nil, nil,
		)
		if err := finding.ValidateFindingRefs(missingTarget); err == nil {
			t.Fatal("expected missing affected_target_id failure")
		}
	})

	t.Run("execution", func(t *testing.T) {
		t.Parallel()
		var event domain.ExecutionEvent
		if err := domain.DecodeAndValidateJSON(readFixture(t, "valid", "execution-event.json"), &event); err != nil {
			t.Fatalf("decode execution: %v", err)
		}
		good := domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-disk-nvme0n1"},
			nil, nil, nil,
			[]string{"artifact-111111111111111111111111"},
		)
		if err := event.ValidateExecutionRefs(good); err != nil {
			t.Fatalf("ValidateExecutionRefs() error = %v", err)
		}
		if err := event.ValidateExecutionRefs(domain.NewCrossRefs(
			[]string{"case-000000000000000000000000"},
			[]string{"target-disk-nvme0n1"},
			nil, nil, nil,
			[]string{"artifact-111111111111111111111111"},
		)); err == nil {
			t.Fatal("expected missing case_id failure")
		}
		if err := event.ValidateExecutionRefs(domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-000000000000000000000000"},
			nil, nil, nil,
			[]string{"artifact-111111111111111111111111"},
		)); err == nil {
			t.Fatal("expected missing target_id failure")
		}
		if err := event.ValidateExecutionRefs(domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-disk-nvme0n1"},
			nil, nil, nil,
			[]string{"artifact-000000000000000000000000"},
		)); err == nil {
			t.Fatal("expected missing stdout_artifact failure")
		}

		var failed domain.ExecutionEvent
		if err := domain.DecodeAndValidateJSON(readFixture(t, "valid", "execution-event-failed.json"), &failed); err != nil {
			t.Fatalf("decode failed execution: %v", err)
		}
		if err := failed.ValidateExecutionRefs(domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-disk-nvme0n1"},
			nil, nil, nil,
			[]string{"artifact-222222222222222222222222"},
		)); err != nil {
			t.Fatalf("ValidateExecutionRefs(failed) error = %v", err)
		}
		if err := failed.ValidateExecutionRefs(domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			[]string{"target-disk-nvme0n1"},
			nil, nil, nil,
			[]string{"artifact-000000000000000000000000"},
		)); err == nil {
			t.Fatal("expected missing stderr_artifact failure")
		}
	})

	t.Run("verification", func(t *testing.T) {
		t.Parallel()
		var report domain.VerificationReport
		if err := domain.DecodeAndValidateJSON(readFixture(t, "valid", "verification-report.json"), &report); err != nil {
			t.Fatalf("decode verification: %v", err)
		}
		good := domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			nil,
			[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
			nil,
			[]string{"exec-eeeeeeeeeeeeeeeeeeeeeeee"},
			nil,
		)
		if err := report.ValidateVerificationRefs(good); err != nil {
			t.Fatalf("ValidateVerificationRefs() error = %v", err)
		}
		if err := report.ValidateVerificationRefs(domain.NewCrossRefs(
			[]string{"case-000000000000000000000000"},
			nil,
			[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
			nil,
			[]string{"exec-eeeeeeeeeeeeeeeeeeeeeeee"},
			nil,
		)); err == nil {
			t.Fatal("expected missing case_id failure")
		}
		if err := report.ValidateVerificationRefs(domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			nil,
			[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
			nil,
			[]string{"exec-000000000000000000000000"},
			nil,
		)); err == nil {
			t.Fatal("expected missing execution_id failure")
		}
		if err := report.ValidateVerificationRefs(domain.NewCrossRefs(
			[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
			nil,
			[]string{"evidence-000000000000000000000000"},
			nil,
			[]string{"exec-eeeeeeeeeeeeeeeeeeeeeeee"},
			nil,
		)); err == nil {
			t.Fatal("expected missing evidence_ref failure")
		}
	})
}

func TestAbsolutePathRejected(t *testing.T) {
	t.Parallel()
	a := domain.ArtifactRef{
		ArtifactID:          "artifact-111111111111111111111111",
		Kind:                "log",
		RelativePath:        `C:\Windows\system32\config`,
		SHA256:              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes:           1,
		CreatedAt:           "2026-07-27T12:00:00Z",
		MediaClassification: "case_local",
	}
	if err := a.Validate(); err == nil {
		t.Fatal("expected absolute path rejection")
	}
}
