package coordinator

import (
	"errors"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestMergePlansImmutableIdenticalNoOp(t *testing.T) {
	t.Parallel()
	plan := domain.RepairPlan{
		SchemaName: domain.SchemaRepairPlan, SchemaVersion: domain.SchemaVersion,
		PlanID: "plan-dddddddddddddddddddddddd", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		FindingRefs: []string{"finding-cccccccccccccccccccccccc"},
		Steps: []domain.PlanStep{{
			StepID: "step-1", OperationID: "boot.inspect_bcd", OperationVersion: "1.0.0",
			TargetID: "target-disk-nvme0n1", DependsOn: []string{},
		}},
		RiskSummary:        "Read-only BCD inspection only.",
		BackupRequirements: []string{}, ApprovalRequirements: []string{},
		Status: "draft",
	}
	merged, err := mergePlansImmutable([]domain.RepairPlan{plan}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 1 {
		t.Fatalf("want 1 plan, got %d", len(merged))
	}
}

func TestMergePlansImmutableDivergentRejected(t *testing.T) {
	t.Parallel()
	existing := domain.RepairPlan{
		SchemaName: domain.SchemaRepairPlan, SchemaVersion: domain.SchemaVersion,
		PlanID: "plan-dddddddddddddddddddddddd", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		FindingRefs: []string{"finding-cccccccccccccccccccccccc"},
		Steps: []domain.PlanStep{{
			StepID: "step-1", OperationID: "boot.inspect_bcd", OperationVersion: "1.0.0",
			TargetID: "target-disk-nvme0n1", DependsOn: []string{},
		}},
		RiskSummary:        "Read-only BCD inspection only.",
		BackupRequirements: []string{}, ApprovalRequirements: []string{},
		Status: "draft",
	}
	divergent := existing
	divergent.RiskSummary = "changed summary"
	_, err := mergePlansImmutable([]domain.RepairPlan{existing}, divergent)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
}
