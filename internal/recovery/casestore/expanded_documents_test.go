package casestore

import (
	"context"
	"errors"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func sampleFinding() domain.Finding {
	return domain.Finding{
		SchemaName:           domain.SchemaFinding,
		SchemaVersion:        domain.SchemaVersion,
		FindingID:            "finding-cccccccccccccccccccccccc",
		CaseID:               "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		Severity:             "high",
		Confidence:           "medium",
		Title:                "ESP present but boot entry missing",
		Rationale:            "Disk inventory shows an EFI system partition while BCD enumeration found no matching Windows boot entry.",
		EvidenceRefs:         []string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
		AffectedTargetIDs:    []string{"target-disk-nvme0n1"},
		RecommendedWorkflows: []string{"boot-doctor"},
		Limitations:          []string{"BCD store may be on another disk"},
	}
}

func samplePlan() domain.RepairPlan {
	return domain.RepairPlan{
		SchemaName:    domain.SchemaRepairPlan,
		SchemaVersion: domain.SchemaVersion,
		PlanID:        "plan-dddddddddddddddddddddddd",
		CaseID:        "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		FindingRefs:   []string{"finding-cccccccccccccccccccccccc"},
		Steps: []domain.PlanStep{{
			StepID:           "step-1",
			OperationID:      "boot.inspect_bcd",
			OperationVersion: "1.0.0",
			TargetID:         "target-disk-nvme0n1",
			DependsOn:        []string{},
		}},
		RiskSummary:          "Read-only BCD inspection only.",
		BackupRequirements:   []string{},
		ApprovalRequirements: []string{},
		Status:               "draft",
	}
}

func sampleExecution() domain.ExecutionEvent {
	return domain.ExecutionEvent{
		SchemaName:       domain.SchemaExecutionEvent,
		SchemaVersion:    domain.SchemaVersion,
		ExecutionID:      "exec-eeeeeeeeeeeeeeeeeeeeeeee",
		CaseID:           "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		OperationID:      "boot.inspect_bcd",
		OperationVersion: "1.0.0",
		TargetID:         "target-disk-nvme0n1",
		StartedAt:        "2026-07-27T12:10:00Z",
		Status:           "started",
		ChangedResources: []string{},
	}
}

func sampleVerification() domain.VerificationReport {
	return domain.VerificationReport{
		SchemaName:     domain.SchemaVerificationReport,
		SchemaVersion:  domain.SchemaVersion,
		VerificationID: "verify-ffffffffffffffffffffffff",
		CaseID:         "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		ExecutionID:    "exec-eeeeeeeeeeeeeeeeeeeeeeee",
		Verifier:       "boot-verify",
		VerifiedAt:     "2026-07-27T12:11:00Z",
		ExpectedConditions: []domain.ConditionCheck{
			{Name: "bcd_readable", Status: "met"},
		},
		ObservedConditions: []domain.ConditionCheck{
			{Name: "bcd_readable", Status: "met", Detail: "store opened"},
		},
		Status:         "resolved",
		Regressions:    []string{},
		RemainingRisks: []string{"boot chain not tested by reboot"},
		EvidenceRefs:   []string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
	}
}

func sampleCoordinatorEvent() domain.CoordinatorEvent {
	return domain.CoordinatorEvent{
		SchemaName:       domain.SchemaCoordinatorEvent,
		SchemaVersion:    domain.SchemaVersion,
		EventID:          "cevt-111111111111111111111111",
		CaseID:           "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		EventType:        domain.EventCaseCreated,
		ActorType:        domain.ActorSystem,
		OccurredAt:       "2026-07-27T12:05:00Z",
		PreviousState:    string(domain.WorkflowCreated),
		NextState:        string(domain.WorkflowEvidenceCollected),
		WorkflowRevision: 1,
		ReferencedDocumentIDs: []string{
			"case-aaaaaaaaaaaaaaaaaaaaaaaa",
			"target-disk-nvme0n1",
			"evidence-bbbbbbbbbbbbbbbbbbbbbbbb",
			domain.DocumentIDCaseWorkflowState,
		},
		ReasonCode: "legacy_import_committed",
	}
}

func sampleWorkflow() *domain.CaseWorkflowState {
	return &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		State:            domain.WorkflowEvidenceCollected,
		Revision:         1,
		UpdatedAt:        "2026-07-27T12:05:00Z",
		LastTransitionID: "cevt-111111111111111111111111",
	}
}

func enrichedSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snap := baseSnapshot(t)
	snap.Findings = []domain.Finding{sampleFinding()}
	snap.RepairPlans = []domain.RepairPlan{samplePlan()}
	snap.ExecutionEvents = []domain.ExecutionEvent{sampleExecution()}
	snap.VerificationReports = []domain.VerificationReport{sampleVerification()}
	snap.CoordinatorEvents = []domain.CoordinatorEvent{sampleCoordinatorEvent()}
	snap.WorkflowState = sampleWorkflow()
	return snap
}

func analyzedSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snap := baseSnapshot(t)
	snap.Findings = []domain.Finding{sampleFinding()}
	snap.Case.CurrentState = domain.CaseStateDiagnosed
	snap.Case.UpdatedAt = "2026-07-27T12:06:00Z"
	snap.CoordinatorEvents = []domain.CoordinatorEvent{
		sampleCoordinatorEvent(),
		{
			SchemaName:       domain.SchemaCoordinatorEvent,
			SchemaVersion:    domain.SchemaVersion,
			EventID:          "cevt-222222222222222222222222",
			CaseID:           snap.Case.CaseID,
			EventType:        domain.EventAnalysisCommitted,
			ActorType:        domain.ActorDeterministicAnalyzer,
			OccurredAt:       "2026-07-27T12:06:00Z",
			PreviousState:    string(domain.WorkflowEvidenceCollected),
			NextState:        string(domain.WorkflowAnalyzed),
			ExpectedCommitID: "commit-111111111111111111111111",
			WorkflowRevision: 2,
			ReferencedDocumentIDs: []string{
				snap.Case.CaseID,
				sampleFinding().FindingID,
				snap.EvidenceBundles[0].EvidenceID,
				snap.Targets[0].TargetID,
				domain.DocumentIDCaseWorkflowState,
			},
			ReasonCode: "analysis_committed",
		},
	}
	snap.WorkflowState = &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           snap.Case.CaseID,
		State:            domain.WorkflowAnalyzed,
		Revision:         2,
		UpdatedAt:        snap.Case.UpdatedAt,
		LastTransitionID: "cevt-222222222222222222222222",
	}
	return snap
}

func plannedSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snap := analyzedSnapshot(t)
	snap.RepairPlans = []domain.RepairPlan{samplePlan()}
	snap.Case.CurrentState = domain.CaseStatePlanned
	snap.Case.UpdatedAt = "2026-07-27T12:07:00Z"
	snap.CoordinatorEvents = append(snap.CoordinatorEvents, domain.CoordinatorEvent{
		SchemaName:       domain.SchemaCoordinatorEvent,
		SchemaVersion:    domain.SchemaVersion,
		EventID:          "cevt-333333333333333333333333",
		CaseID:           snap.Case.CaseID,
		EventType:        domain.EventPlanCommitted,
		ActorType:        domain.ActorSystem,
		OccurredAt:       "2026-07-27T12:07:00Z",
		PreviousState:    string(domain.WorkflowAnalyzed),
		NextState:        string(domain.WorkflowPlanProposed),
		ExpectedCommitID: "commit-222222222222222222222222",
		WorkflowRevision: 3,
		ReferencedDocumentIDs: []string{
			snap.Case.CaseID,
			samplePlan().PlanID,
			samplePlan().FindingRefs[0],
			snap.Targets[0].TargetID,
			domain.DocumentIDCaseWorkflowState,
		},
		ReasonCode: "plan_committed",
	})
	snap.WorkflowState = &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           snap.Case.CaseID,
		State:            domain.WorkflowPlanProposed,
		Revision:         3,
		UpdatedAt:        snap.Case.UpdatedAt,
		LastTransitionID: "cevt-333333333333333333333333",
		ActivePlanID:     samplePlan().PlanID,
	}
	return snap
}

func failedSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snap := analyzedSnapshot(t)
	snap.Case.CurrentState = domain.CaseStateFailed
	snap.Case.UpdatedAt = "2026-07-27T12:07:00Z"
	snap.CoordinatorEvents = append(snap.CoordinatorEvents, domain.CoordinatorEvent{
		SchemaName:       domain.SchemaCoordinatorEvent,
		SchemaVersion:    domain.SchemaVersion,
		EventID:          "cevt-444444444444444444444444",
		CaseID:           snap.Case.CaseID,
		EventType:        domain.EventCaseFailed,
		ActorType:        domain.ActorTechnician,
		OccurredAt:       "2026-07-27T12:07:00Z",
		PreviousState:    string(domain.WorkflowAnalyzed),
		NextState:        string(domain.WorkflowFailed),
		ExpectedCommitID: "commit-333333333333333333333333",
		WorkflowRevision: 3,
		ReferencedDocumentIDs: []string{
			snap.Case.CaseID,
			domain.DocumentIDCaseWorkflowState,
		},
		ReasonCode: "case_failed",
	})
	snap.WorkflowState = &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           snap.Case.CaseID,
		State:            domain.WorkflowFailed,
		Revision:         3,
		UpdatedAt:        snap.Case.UpdatedAt,
		LastTransitionID: "cevt-444444444444444444444444",
		Failure:          &domain.WorkflowFailure{ReasonCode: "case_failed"},
	}
	return snap
}

func TestLegacySnapshotWithoutNewDocumentsLoads(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonLegacyImport)
	loaded, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID {
		t.Fatalf("commit id mismatch")
	}
	if loaded.WorkflowState != nil {
		t.Fatalf("expected nil workflow on legacy snapshot")
	}
	if len(loaded.Findings) != 0 || len(loaded.RepairPlans) != 0 ||
		len(loaded.ExecutionEvents) != 0 || len(loaded.VerificationReports) != 0 ||
		len(loaded.CoordinatorEvents) != 0 {
		t.Fatalf("expected empty new collections, got %#v", loaded)
	}
}

func TestExpandedDocumentsRoundTrip(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := enrichedSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	loaded, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID || got.SnapshotID != info.SnapshotID {
		t.Fatalf("commit mismatch: %+v vs %+v", got, info)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].FindingID != sampleFinding().FindingID {
		t.Fatalf("findings: %+v", loaded.Findings)
	}
	if len(loaded.RepairPlans) != 1 || loaded.RepairPlans[0].PlanID != samplePlan().PlanID {
		t.Fatalf("plans: %+v", loaded.RepairPlans)
	}
	if len(loaded.ExecutionEvents) != 1 || loaded.ExecutionEvents[0].ExecutionID != sampleExecution().ExecutionID {
		t.Fatalf("executions: %+v", loaded.ExecutionEvents)
	}
	if len(loaded.VerificationReports) != 1 || loaded.VerificationReports[0].VerificationID != sampleVerification().VerificationID {
		t.Fatalf("verifications: %+v", loaded.VerificationReports)
	}
	if len(loaded.CoordinatorEvents) != 1 || loaded.CoordinatorEvents[0].EventID != sampleCoordinatorEvent().EventID {
		t.Fatalf("events: %+v", loaded.CoordinatorEvents)
	}
	if loaded.WorkflowState == nil || loaded.WorkflowState.State != domain.WorkflowEvidenceCollected {
		t.Fatalf("workflow: %+v", loaded.WorkflowState)
	}
	docs, err := prepareDocuments(loaded)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := map[string]struct{}{
		"case-manifest.json":                                    {},
		"case-workflow-state.json":                              {},
		"targets/target-disk-nvme0n1.json":                      {},
		"evidence/evidence-bbbbbbbbbbbbbbbbbbbbbbbb.json":       {},
		"findings/finding-cccccccccccccccccccccccc.json":        {},
		"plans/plan-dddddddddddddddddddddddd.json":              {},
		"executions/exec-eeeeeeeeeeeeeeeeeeeeeeee.json":         {},
		"verifications/verify-ffffffffffffffffffffffff.json":    {},
		"coordinator-events/cevt-111111111111111111111111.json": {},
	}
	if len(docs) != len(wantPaths) {
		t.Fatalf("doc count %d want %d", len(docs), len(wantPaths))
	}
	for _, d := range docs {
		if _, ok := wantPaths[d.RelativePath]; !ok {
			t.Fatalf("unexpected path %s", d.RelativePath)
		}
	}
}

func TestDeterministicSnapshotHashWithExpandedDocs(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	docsA, err := prepareDocuments(snap)
	if err != nil {
		t.Fatal(err)
	}
	docsB, err := prepareDocuments(snap)
	if err != nil {
		t.Fatal(err)
	}
	manA, _, err := buildSnapshotManifest(snap.Case.CaseID, snap.Case.UpdatedAt, docsA, nil)
	if err != nil {
		t.Fatal(err)
	}
	manB, _, err := buildSnapshotManifest(snap.Case.CaseID, snap.Case.UpdatedAt, docsB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if manA.SnapshotID != manB.SnapshotID || manA.ContentSHA256 != manB.ContentSHA256 {
		t.Fatalf("non-deterministic snapshot hash")
	}
}

func TestDuplicateFindingIDRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.Findings = append(snap.Findings, sampleFinding())
	if err := snap.Validate(); err == nil {
		t.Fatal("expected duplicate finding rejection")
	}
}

func TestBrokenFindingEvidenceRefRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.Findings[0].EvidenceRefs = []string{"evidence-000000000000000000000000"}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected broken evidence ref rejection")
	}
}

func TestBrokenFindingTargetRefRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.Findings[0].AffectedTargetIDs = []string{"target-missing-disk-01"}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected broken target ref rejection")
	}
}

func TestBrokenRepairPlanRefRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.RepairPlans[0].FindingRefs = []string{"finding-000000000000000000000000"}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected broken plan finding ref rejection")
	}
}

func TestBrokenExecutionEventRefRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.ExecutionEvents[0].TargetID = "target-missing-disk-01"
	if err := snap.Validate(); err == nil {
		t.Fatal("expected broken execution target rejection")
	}
}

func TestBrokenVerificationReportRefRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.VerificationReports[0].ExecutionID = "exec-000000000000000000000000"
	if err := snap.Validate(); err == nil {
		t.Fatal("expected broken verification execution ref rejection")
	}
}

func TestIncompatibleWorkflowManifestRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.Case.CurrentState = domain.CaseStateNew // incompatible with evidence_collected workflow
	if err := snap.Validate(); err == nil {
		t.Fatal("expected incompatible workflow/manifest pair rejection")
	}
}

func TestFilenameIDMismatchRejectedOnLoad(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := enrichedSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	newID, manifestSHA := tamperSnapshotDocument(t, st, snap.Case.CaseID, info.SnapshotID, "findings/finding-cccccccccccccccccccccccc.json", func(raw []byte) []byte {
		// Keep bytes valid JSON finding but change finding_id so path != id.
		mut := sampleFinding()
		mut.FindingID = "finding-999999999999999999999999"
		out, err := marshalCanonical(mut)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	_, err := st.loadSnapshotAtCommit(snap.Case.CaseID, commitRecord{
		CaseID:                 snap.Case.CaseID,
		SnapshotID:             newID,
		SnapshotManifestSHA256: manifestSHA,
	})
	if err == nil {
		t.Fatal("expected path/id mismatch rejection")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}

func TestLifecycleDocumentsRequireWorkflowState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"finding", func(s *Snapshot) { s.Findings = []domain.Finding{sampleFinding()} }},
		{"plan", func(s *Snapshot) { s.RepairPlans = []domain.RepairPlan{samplePlan()} }},
		{"execution", func(s *Snapshot) { s.ExecutionEvents = []domain.ExecutionEvent{sampleExecution()} }},
		{"verification", func(s *Snapshot) { s.VerificationReports = []domain.VerificationReport{sampleVerification()} }},
		{"event", func(s *Snapshot) { s.CoordinatorEvents = []domain.CoordinatorEvent{sampleCoordinatorEvent()} }},
		{"multiple", func(s *Snapshot) {
			s.Findings = []domain.Finding{sampleFinding()}
			s.RepairPlans = []domain.RepairPlan{samplePlan()}
			s.CoordinatorEvents = []domain.CoordinatorEvent{sampleCoordinatorEvent()}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snap := baseSnapshot(t)
			test.mutate(&snap)
			if err := snap.Validate(); err == nil {
				t.Fatal("expected workflow_state requirement rejection")
			}
		})
	}
}

func TestWorkflowStateSemanticsPlanProposedRequiresActivePlan(t *testing.T) {
	t.Parallel()
	snap := plannedSnapshot(t)
	snap.WorkflowState.ActivePlanID = ""
	if err := snap.Validate(); err == nil {
		t.Fatal("expected missing active_plan_id rejection")
	}
}

func TestWorkflowStateSemanticsFailedRequiresFailure(t *testing.T) {
	t.Parallel()
	snap := failedSnapshot(t)
	snap.WorkflowState.Failure = nil
	if err := snap.Validate(); err == nil {
		t.Fatal("expected missing failure rejection")
	}
}

func TestWorkflowStateSemanticsCancelledForbidsFailure(t *testing.T) {
	t.Parallel()
	snap := failedSnapshot(t)
	snap.Case.CurrentState = domain.CaseStateCancelled
	snap.WorkflowState.State = domain.WorkflowCancelled
	snap.CoordinatorEvents[len(snap.CoordinatorEvents)-1].EventType = domain.EventCaseCancelled
	snap.CoordinatorEvents[len(snap.CoordinatorEvents)-1].NextState = string(domain.WorkflowCancelled)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected cancelled failure rejection")
	}
}

func TestWorkflowStateSemanticsCreatedNotPersisted(t *testing.T) {
	t.Parallel()
	snap := baseSnapshot(t)
	snap.WorkflowState = &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           snap.Case.CaseID,
		State:            domain.WorkflowCreated,
		Revision:         1,
		UpdatedAt:        snap.Case.UpdatedAt,
		LastTransitionID: "cevt-111111111111111111111111",
	}
	snap.CoordinatorEvents = []domain.CoordinatorEvent{sampleCoordinatorEvent()}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected persisted created rejection")
	}
}

func TestWorkflowStateSemanticsTimestampMismatchRejected(t *testing.T) {
	t.Parallel()
	snap := analyzedSnapshot(t)
	snap.WorkflowState.UpdatedAt = "2026-07-27T12:07:00Z"
	if err := snap.Validate(); err == nil {
		t.Fatal("expected workflow/case updated_at mismatch rejection")
	}
}

func TestAnalysisEventReferenceSemanticsRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"missing finding", func(s *Snapshot) {
			s.CoordinatorEvents[1].ReferencedDocumentIDs = []string{s.Case.CaseID, s.EvidenceBundles[0].EvidenceID, s.Targets[0].TargetID, domain.DocumentIDCaseWorkflowState}
		}},
		{"missing evidence", func(s *Snapshot) {
			s.CoordinatorEvents[1].ReferencedDocumentIDs = []string{s.Case.CaseID, s.Findings[0].FindingID, s.Targets[0].TargetID, domain.DocumentIDCaseWorkflowState}
		}},
		{"missing target", func(s *Snapshot) {
			s.CoordinatorEvents[1].ReferencedDocumentIDs = []string{s.Case.CaseID, s.Findings[0].FindingID, s.EvidenceBundles[0].EvidenceID, domain.DocumentIDCaseWorkflowState}
		}},
		{"unrelated plan", func(s *Snapshot) {
			s.CoordinatorEvents[1].ReferencedDocumentIDs = append(s.CoordinatorEvents[1].ReferencedDocumentIDs, samplePlan().PlanID)
			s.RepairPlans = []domain.RepairPlan{samplePlan()}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snap := analyzedSnapshot(t)
			test.mutate(&snap)
			if err := snap.Validate(); err == nil {
				t.Fatal("expected analysis ref semantics rejection")
			}
		})
	}
}

func TestPlanEventReferenceSemanticsRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"missing plan", func(s *Snapshot) {
			s.CoordinatorEvents[len(s.CoordinatorEvents)-1].ReferencedDocumentIDs = []string{s.Case.CaseID, s.Findings[0].FindingID, s.Targets[0].TargetID, domain.DocumentIDCaseWorkflowState}
		}},
		{"two plans", func(s *Snapshot) {
			other := samplePlan()
			other.PlanID = "plan-eeeeeeeeeeeeeeeeeeeeeeee"
			s.RepairPlans = append(s.RepairPlans, other)
			s.CoordinatorEvents[len(s.CoordinatorEvents)-1].ReferencedDocumentIDs = append(s.CoordinatorEvents[len(s.CoordinatorEvents)-1].ReferencedDocumentIDs, other.PlanID)
		}},
		{"missing finding", func(s *Snapshot) {
			s.CoordinatorEvents[len(s.CoordinatorEvents)-1].ReferencedDocumentIDs = []string{s.Case.CaseID, s.RepairPlans[0].PlanID, s.Targets[0].TargetID, domain.DocumentIDCaseWorkflowState}
		}},
		{"unrelated event id", func(s *Snapshot) {
			s.CoordinatorEvents[len(s.CoordinatorEvents)-1].ReferencedDocumentIDs = append(s.CoordinatorEvents[len(s.CoordinatorEvents)-1].ReferencedDocumentIDs, "cevt-999999999999999999999999")
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snap := plannedSnapshot(t)
			test.mutate(&snap)
			if err := snap.Validate(); err == nil {
				t.Fatal("expected plan ref semantics rejection")
			}
		})
	}
}

func TestCoordinatorEventSelfReferenceRejected(t *testing.T) {
	t.Parallel()
	snap := analyzedSnapshot(t)
	snap.CoordinatorEvents[1].ReferencedDocumentIDs = append(snap.CoordinatorEvents[1].ReferencedDocumentIDs, snap.CoordinatorEvents[1].EventID)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected self-reference rejection")
	}
}

func TestTerminalEventExtraRefRejected(t *testing.T) {
	t.Parallel()
	snap := failedSnapshot(t)
	snap.CoordinatorEvents[len(snap.CoordinatorEvents)-1].ReferencedDocumentIDs = append(
		snap.CoordinatorEvents[len(snap.CoordinatorEvents)-1].ReferencedDocumentIDs,
		snap.Findings[0].FindingID,
	)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected terminal extra ref rejection")
	}
}
