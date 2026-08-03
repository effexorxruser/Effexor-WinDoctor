package bootdoctor

// Suppression / precedence rules (documented and enforced):
//
// 1. windows_installation_missing suppresses secondary BCD membership findings
//    that assume a selected Windows installation exists.
// 2. firmware_mode_conflicting / firmware_mode_unknown suppress confident
//    boot_topology_consistent and layout-specific certainty beyond the conflict itself.
// 3. bitlocker_locked suppresses conclusions that imply Windows filesystem damage;
//    locked volumes remain inaccessible, not proven corrupt.
// 4. storage_health_critical always emits unsafe_to_attempt_boot_repair and keeps
//    other confirmed findings, but suppresses boot_topology_consistent.
// 5. Ambiguous/incomplete topology suppresses boot_topology_consistent and does
//    not invent a silent single-target selection.
// 6. When multiple Windows installations exist, BCD-for-selected-Windows findings
//    are suppressed until technician selection resolves the Windows role.
// 7. Critical cross-disk findings keep unsafe_to_attempt_boot_repair.

var suppressWhenPresent = map[string][]string{
	CodeWindowsInstallationMissing: {
		CodeBCDMembershipUnknown,
		CodeBCDWindowsEntryMissing,
		CodeBCDPointsToUnknownInstallation,
		CodeWindowsPartitionRelationUnknown,
		CodeWindowsSystemDiskRelationUnknown,
		CodeWindowsInstallationIncomplete,
	},
	CodeMultipleWindowsInstallations: {
		CodeBCDMembershipUnknown,
		CodeBCDWindowsEntryMissing,
		CodeBCDPointsToUnknownInstallation,
	},
	CodeWindowsInstallationAmbiguous: {
		CodeBCDMembershipUnknown,
		CodeBCDWindowsEntryMissing,
		CodeBCDPointsToUnknownInstallation,
	},
	CodeFirmwareModeConflicting: {
		CodeBootTopologyConsistent,
		CodeUEFIWithMBRSystemDisk,
		CodeLegacyWithGPTLayout,
	},
	CodeFirmwareModeUnknown: {
		CodeBootTopologyConsistent,
		CodeUEFIWithMBRSystemDisk,
		CodeLegacyWithGPTLayout,
	},
	CodeBitLockerLocked: {
		// Do not imply filesystem damage findings; none are emitted today.
		CodeBootTopologyConsistent,
	},
	CodeBitLockerStatusUnknown: {
		CodeBootTopologyConsistent,
	},
	CodeStorageHealthCritical: {
		CodeBootTopologyConsistent,
	},
	CodeStorageHealthUnknown: {
		CodeBootTopologyConsistent,
	},
	CodeStorageEvidenceMissing: {
		CodeBootTopologyConsistent,
	},
	CodeBootTopologyAmbiguous: {
		CodeBootTopologyConsistent,
	},
	CodeBootTopologyIncomplete: {
		CodeBootTopologyConsistent,
	},
	CodeBootTopologyConflicting: {
		CodeBootTopologyConsistent,
	},
	CodeEFISystemPartitionCrossDisk: {
		CodeBootTopologyConsistent,
	},
	CodeBCDCrossDiskMismatch: {
		CodeBootTopologyConsistent,
	},
}

func applySuppression(codes map[string]draft) map[string]draft {
	drop := make(map[string]struct{})
	for present := range codes {
		for _, victim := range suppressWhenPresent[present] {
			drop[victim] = struct{}{}
		}
	}
	if len(drop) == 0 {
		return codes
	}
	out := make(map[string]draft, len(codes))
	for code, d := range codes {
		if _, skip := drop[code]; skip {
			continue
		}
		out[code] = d
	}
	return out
}
