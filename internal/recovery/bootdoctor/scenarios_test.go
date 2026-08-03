package bootdoctor_test

import (
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestScenarioHealthyUEFIGPT(t *testing.T) {
	t.Parallel()
	fix := resolveFixture(t, topologySnapshot(t, "uefi", true), testNow)
	if !fix.Topology.MutationEligibility.Eligible {
		t.Fatalf("expected eligible topology: %v", fix.Topology.MutationEligibility.Blockers)
	}
	res := analyzeFixture(t, fix, fix.Evidence.EvidenceID)
	assertHasCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioWindowsMissing(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, snapshotWithoutWindows(t, topologySnapshot(t, "uefi", true)))
	assertHasCode(t, res.Findings, bootdoctor.CodeWindowsInstallationMissing)
}

func TestScenarioMultipleWindows(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, snapshotWithSecondWindows(t, topologySnapshot(t, "uefi", true)))
	assertHasCode(t, res.Findings, bootdoctor.CodeMultipleWindowsInstallations)
	assertHasCode(t, res.Findings, bootdoctor.CodeWindowsInstallationAmbiguous)
	assertHasCode(t, res.Findings, bootdoctor.CodeBootTopologyAmbiguous)
}

func TestScenarioESPMissing(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, snapshotWithoutESP(t, topologySnapshot(t, "uefi", true)))
	assertHasCode(t, res.Findings, bootdoctor.CodeEFISystemPartitionMissing)
}

func TestScenarioMultipleESP(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, snapshotWithSecondESP(t, topologySnapshot(t, "uefi", true)))
	assertHasCode(t, res.Findings, bootdoctor.CodeMultipleEFISystemPartitions)
	assertHasCode(t, res.Findings, bootdoctor.CodeEFISystemPartitionAmbiguous)
}

func TestScenarioESPCrossDisk(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshotDisconnected(t))
	assertHasCode(t, res.Findings, bootdoctor.CodeEFISystemPartitionCrossDisk)
	assertHasCode(t, res.Findings, bootdoctor.CodeUnsafeToAttemptBootRepair)
	assertHasCode(t, res.Findings, bootdoctor.CodeTechnicianSelectionRequired)
}

func TestScenarioBCDMissingWithSelection(t *testing.T) {
	t.Parallel()
	fix := resolveFixture(t, topologySnapshot(t, "uefi", true), testNow)
	if fix.Topology.Selection.Source == domain.SelectionNone {
		t.Fatal("expected automatic selection for baseline fixture")
	}
	topo := topologyWithoutBDCCandidates(t, fix)
	res := analyzeFixture(t, resolvedFixture{Snap: fix.Snap, Topology: topo, Evidence: fix.Evidence}, fix.Evidence.EvidenceID)
	assertHasCode(t, res.Findings, bootdoctor.CodeBCDStoreMissing)
}

func TestScenarioBitLockerLocked(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshotWithBitLocker(t, "locked"))
	assertHasCode(t, res.Findings, bootdoctor.CodeBitLockerLocked)
	assertHasCode(t, res.Findings, bootdoctor.CodeBitLockerRecoveryMaterialRequired)
	assertHasCode(t, res.Findings, bootdoctor.CodeBitLockerBlocksBootAnalysis)
	assertLacksCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioBitLockerUnknown(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshotWithBitLocker(t, ""))
	assertHasCode(t, res.Findings, bootdoctor.CodeBitLockerStatusUnknown)
	assertHasCode(t, res.Findings, bootdoctor.CodeBitLockerBlocksBootAnalysis)
	assertLacksCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioStorageHealthCritical(t *testing.T) {
	t.Parallel()
	snap := snapshotWithStorageHealth(t, topologySnapshot(t, "uefi", true), []map[string]any{
		{"device_id": "0", "health_status": "Critical", "operational_status": "Failed"},
	})
	res := analyzeResolved(t, snap)
	assertHasCode(t, res.Findings, bootdoctor.CodeStorageHealthCritical)
	assertHasCode(t, res.Findings, bootdoctor.CodeUnsafeToAttemptBootRepair)
	assertLacksCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioStorageHealthUnknown(t *testing.T) {
	t.Parallel()
	snap := snapshotWithStorageHealth(t, topologySnapshot(t, "uefi", true), []map[string]any{
		{"device_id": "0", "health_status": "", "operational_status": "unknown"},
	})
	res := analyzeResolved(t, snap)
	assertHasCode(t, res.Findings, bootdoctor.CodeStorageHealthUnknown)
	assertLacksCode(t, res.Findings, bootdoctor.CodeStorageEvidenceMissing)
	assertLacksCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioStorageEvidenceMissing(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, snapshotWithoutDriveHealth(t, topologySnapshot(t, "uefi", true)))
	assertHasCode(t, res.Findings, bootdoctor.CodeStorageEvidenceMissing)
	assertHasCode(t, res.Findings, bootdoctor.CodeStorageHealthUnknown)
	assertLacksCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioFirmwareConflicting(t *testing.T) {
	t.Parallel()
	snap := snapshotWithConflictingFirmware(t, topologySnapshot(t, "uefi", true))
	res := analyzeResolved(t, snap)
	assertHasCode(t, res.Findings, bootdoctor.CodeFirmwareModeConflicting)
	assertHasCode(t, res.Findings, bootdoctor.CodeBootTopologyConflicting)
	assertLacksCode(t, res.Findings, bootdoctor.CodeBootTopologyConsistent)
}

func TestScenarioUEFIWithMBR(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshot(t, "uefi", false))
	assertHasCode(t, res.Findings, bootdoctor.CodeUEFIWithMBRSystemDisk)
}

func TestScenarioLegacyBIOSWithGPT(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshot(t, "bios", true))
	assertHasCode(t, res.Findings, bootdoctor.CodeLegacyWithGPTLayout)
	assertHasCode(t, res.Findings, bootdoctor.CodeUnsupportedLegacyBootTopology)
	assertHasCode(t, res.Findings, bootdoctor.CodeTechnicianSelectionRequired)
}

func TestScenarioIncompleteTechnicianSelectionRequired(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshotDisconnected(t))
	assertHasCode(t, res.Findings, bootdoctor.CodeTechnicianSelectionRequired)
	assertHasCode(t, res.Findings, bootdoctor.CodeBootTopologyIncomplete)
	assertHasCode(t, res.Findings, bootdoctor.CodeInsufficientEvidenceForRepairPlan)
}
