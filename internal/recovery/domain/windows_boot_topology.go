package domain

import "fmt"

type FirmwareMode string

const (
	FirmwareUEFI        FirmwareMode = "uefi"
	FirmwareBIOS        FirmwareMode = "bios"
	FirmwareUnknown     FirmwareMode = "unknown"
	FirmwareConflicting FirmwareMode = "conflicting"
)

type TopologyConfidence string

const (
	ConfidenceProven          TopologyConfidence = "proven"
	ConfidenceStrongInference TopologyConfidence = "strong_inference"
	ConfidenceRuntimeOnly     TopologyConfidence = "runtime_only"
	ConfidenceAmbiguous       TopologyConfidence = "ambiguous"
	ConfidenceUnknown         TopologyConfidence = "unknown"
)

type TopologyRole string

const (
	RoleWindowsInstallation TopologyRole = "windows_installation"
	RoleWindowsPartition    TopologyRole = "windows_partition"
	RoleSystemDisk          TopologyRole = "system_disk"
	RoleEFISystemPartition  TopologyRole = "efi_system_partition"
	RoleBCDStore            TopologyRole = "bcd_store"
	RoleFirmware            TopologyRole = "firmware"
	RoleBitLockerVolume     TopologyRole = "bitlocker_volume"
)

type TopologyRelationType string

const (
	RelationContains             TopologyRelationType = "contains"
	RelationHostsWindows         TopologyRelationType = "hosts_windows"
	RelationHostsESP             TopologyRelationType = "hosts_esp"
	RelationContainsBCDStore     TopologyRelationType = "contains_bcd_store"
	RelationBootStoreForWindows  TopologyRelationType = "boot_store_for_windows"
	RelationProtectedByBitLocker TopologyRelationType = "protected_by_bitlocker"
	RelationHealthRecordForDisk  TopologyRelationType = "health_record_for_disk"
	RelationRuntimePathMatch     TopologyRelationType = "runtime_path_match"
	RelationLegacyReport         TopologyRelationType = "legacy_report_relation"
	RelationTechnicianSelected   TopologyRelationType = "technician_selected"
)

type SelectionSource string

const (
	SelectionAutomatic  SelectionSource = "automatic"
	SelectionTechnician SelectionSource = "technician"
	SelectionNone       SelectionSource = "none"
)

type MutationEligibilityBasis string

const MutationEligibilityDiagnosticEvidenceOnly MutationEligibilityBasis = "diagnostic_evidence_only"

var (
	firmwareModes = map[string]struct{}{
		string(FirmwareUEFI): {}, string(FirmwareBIOS): {},
		string(FirmwareUnknown): {}, string(FirmwareConflicting): {},
	}
	topologyConfidences = map[string]struct{}{
		string(ConfidenceProven): {}, string(ConfidenceStrongInference): {},
		string(ConfidenceRuntimeOnly): {}, string(ConfidenceAmbiguous): {},
		string(ConfidenceUnknown): {},
	}
	topologyRoles = map[string]struct{}{
		string(RoleWindowsInstallation): {}, string(RoleWindowsPartition): {},
		string(RoleSystemDisk): {}, string(RoleEFISystemPartition): {},
		string(RoleBCDStore): {}, string(RoleFirmware): {},
		string(RoleBitLockerVolume): {},
	}
	topologyRelationTypes = map[string]struct{}{
		string(RelationContains): {}, string(RelationHostsWindows): {},
		string(RelationHostsESP): {}, string(RelationContainsBCDStore): {},
		string(RelationBootStoreForWindows): {}, string(RelationProtectedByBitLocker): {},
		string(RelationHealthRecordForDisk): {}, string(RelationRuntimePathMatch): {},
		string(RelationLegacyReport): {}, string(RelationTechnicianSelected): {},
	}
	selectionSources = map[string]struct{}{
		string(SelectionAutomatic): {}, string(SelectionTechnician): {},
		string(SelectionNone): {},
	}
	mutationBlockers = map[string]struct{}{
		"firmware_unknown": {}, "firmware_conflicting": {}, "firmware_not_uefi": {},
		"disk_layout_unknown": {}, "disk_not_gpt": {}, "windows_missing": {},
		"windows_ambiguous": {}, "windows_partition_unresolved": {},
		"system_disk_unresolved": {}, "esp_missing": {}, "esp_ambiguous": {},
		"bcd_missing": {}, "bcd_ambiguous": {}, "bitlocker_inaccessible": {},
		"bitlocker_status_unknown": {},
		"storage_health_unsafe":    {}, "storage_health_unknown": {},
		"evidence_incomplete": {}, "relation_runtime_only": {},
		"unsupported_layout": {}, "technician_selection_required": {},
	}
)

// WindowsBootTopology is the immutable advisory topology fact payload.
type WindowsBootTopology struct {
	SchemaName          string              `json:"schema_name"`
	SchemaVersion       string              `json:"schema_version"`
	TopologyID          string              `json:"topology_id"`
	CaseID              string              `json:"case_id"`
	ResolverID          string              `json:"resolver_id"`
	ResolverVersion     string              `json:"resolver_version"`
	SourceCommitID      string              `json:"source_commit_id"`
	GeneratedAt         string              `json:"generated_at"`
	FirmwareMode        FirmwareMode        `json:"firmware_mode"`
	Candidates          []TopologyCandidate `json:"candidates"`
	Relations           []TopologyRelation  `json:"relations"`
	Selection           TopologySelection   `json:"selection"`
	Ambiguities         []TopologyAmbiguity `json:"ambiguities"`
	Limitations         []string            `json:"limitations"`
	MutationEligibility MutationEligibility `json:"mutation_eligibility"`
}

type TopologyCandidate struct {
	CandidateID    string             `json:"candidate_id"`
	Role           TopologyRole       `json:"role"`
	TargetID       string             `json:"target_id"`
	Confidence     TopologyConfidence `json:"confidence"`
	EvidenceRefs   []string           `json:"evidence_refs"`
	RationaleCodes []string           `json:"rationale_codes"`
	Limitations    []string           `json:"limitations"`
}

type TopologyRelation struct {
	RelationID     string               `json:"relation_id"`
	RelationType   TopologyRelationType `json:"relation_type"`
	FromTargetID   string               `json:"from_target_id"`
	ToTargetID     string               `json:"to_target_id"`
	Confidence     TopologyConfidence   `json:"confidence"`
	EvidenceRefs   []string             `json:"evidence_refs"`
	RationaleCodes []string             `json:"rationale_codes"`
	Limitations    []string             `json:"limitations"`
}

type TopologySelection struct {
	Source                   SelectionSource `json:"source"`
	WindowsTargetID          string          `json:"windows_target_id,omitempty"`
	WindowsPartitionTargetID string          `json:"windows_partition_target_id,omitempty"`
	SystemDiskTargetID       string          `json:"system_disk_target_id,omitempty"`
	ESPTargetID              string          `json:"esp_target_id,omitempty"`
	BCDTargetID              string          `json:"bcd_target_id,omitempty"`
}

type TopologyAmbiguity struct {
	Code         string   `json:"code"`
	Message      string   `json:"message"`
	TargetIDs    []string `json:"target_ids"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type MutationEligibility struct {
	Eligible bool                     `json:"eligible"`
	Basis    MutationEligibilityBasis `json:"basis"`
	Blockers []string                 `json:"blockers"`
}

func (t WindowsBootTopology) Validate() error {
	if err := requireSchema(t.SchemaName, t.SchemaVersion, SchemaWindowsBootTopology); err != nil {
		return err
	}
	if err := requireMatch("topology_id", t.TopologyID, reTopologyID); err != nil {
		return err
	}
	if err := requireMatch("case_id", t.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("resolver_id", t.ResolverID, reProducerID); err != nil {
		return err
	}
	if err := requireMatch("resolver_version", t.ResolverVersion, reSemver); err != nil {
		return err
	}
	if err := requireMatch("source_commit_id", t.SourceCommitID, reCommitID); err != nil {
		return err
	}
	if err := requireRFC3339("generated_at", t.GeneratedAt); err != nil {
		return err
	}
	if err := requireEnum("firmware_mode", string(t.FirmwareMode), firmwareModes); err != nil {
		return err
	}
	if t.Candidates == nil {
		return fmt.Errorf("candidates is required")
	}
	seenCandidates := make(map[string]struct{}, len(t.Candidates))
	for i, c := range t.Candidates {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("candidates[%d]: %w", i, err)
		}
		if _, ok := seenCandidates[c.CandidateID]; ok {
			return fmt.Errorf("duplicate candidate_id %q", c.CandidateID)
		}
		seenCandidates[c.CandidateID] = struct{}{}
	}
	if t.Relations == nil {
		return fmt.Errorf("relations is required")
	}
	seenRelations := make(map[string]struct{}, len(t.Relations))
	for i, r := range t.Relations {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("relations[%d]: %w", i, err)
		}
		if _, ok := seenRelations[r.RelationID]; ok {
			return fmt.Errorf("duplicate relation_id %q", r.RelationID)
		}
		seenRelations[r.RelationID] = struct{}{}
	}
	if err := t.Selection.Validate(); err != nil {
		return fmt.Errorf("selection: %w", err)
	}
	if t.Ambiguities == nil {
		return fmt.Errorf("ambiguities is required")
	}
	for i, a := range t.Ambiguities {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("ambiguities[%d]: %w", i, err)
		}
	}
	if t.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	for i, lim := range t.Limitations {
		if lim == "" {
			return fmt.Errorf("limitations[%d] must not be empty", i)
		}
	}
	if err := t.MutationEligibility.Validate(); err != nil {
		return fmt.Errorf("mutation_eligibility: %w", err)
	}
	return nil
}

func (c TopologyCandidate) Validate() error {
	if err := requireMatch("candidate_id", c.CandidateID, reProducerID); err != nil {
		return err
	}
	if err := requireEnum("role", string(c.Role), topologyRoles); err != nil {
		return err
	}
	if err := requireMatch("target_id", c.TargetID, reTargetID); err != nil {
		return err
	}
	if err := requireEnum("confidence", string(c.Confidence), topologyConfidences); err != nil {
		return err
	}
	if err := requireUniqueIDList("evidence_refs", c.EvidenceRefs, reEvidenceID); err != nil {
		return err
	}
	if err := requireUniqueIDList("rationale_codes", c.RationaleCodes, reReasonCode); err != nil {
		return err
	}
	if c.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	return nil
}

func (r TopologyRelation) Validate() error {
	if err := requireMatch("relation_id", r.RelationID, reProducerID); err != nil {
		return err
	}
	if err := requireEnum("relation_type", string(r.RelationType), topologyRelationTypes); err != nil {
		return err
	}
	if err := requireMatch("from_target_id", r.FromTargetID, reTargetID); err != nil {
		return err
	}
	if err := requireMatch("to_target_id", r.ToTargetID, reTargetID); err != nil {
		return err
	}
	if err := requireEnum("confidence", string(r.Confidence), topologyConfidences); err != nil {
		return err
	}
	if err := requireUniqueIDList("evidence_refs", r.EvidenceRefs, reEvidenceID); err != nil {
		return err
	}
	if err := requireUniqueIDList("rationale_codes", r.RationaleCodes, reReasonCode); err != nil {
		return err
	}
	if r.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	return nil
}

func (s TopologySelection) Validate() error {
	if err := requireEnum("source", string(s.Source), selectionSources); err != nil {
		return err
	}
	selected := []string{s.WindowsTargetID, s.WindowsPartitionTargetID, s.SystemDiskTargetID, s.ESPTargetID, s.BCDTargetID}
	hasSelected := false
	for _, id := range selected {
		if id == "" {
			continue
		}
		hasSelected = true
		if err := requireMatch("selection_target_id", id, reTargetID); err != nil {
			return err
		}
	}
	if s.Source == SelectionNone && hasSelected {
		return fmt.Errorf("selection source none must not set selected target ids")
	}
	return nil
}

func (a TopologyAmbiguity) Validate() error {
	if err := requireMatch("code", a.Code, reReasonCode); err != nil {
		return err
	}
	if err := requireNonEmpty("message", a.Message); err != nil {
		return err
	}
	if err := requireUniqueIDList("target_ids", a.TargetIDs, reTargetID); err != nil {
		return err
	}
	return requireUniqueIDList("evidence_refs", a.EvidenceRefs, reEvidenceID)
}

func (m MutationEligibility) Validate() error {
	if m.Basis != MutationEligibilityDiagnosticEvidenceOnly {
		return fmt.Errorf("basis must be %q", MutationEligibilityDiagnosticEvidenceOnly)
	}
	if m.Blockers == nil {
		return fmt.Errorf("blockers is required")
	}
	seen := make(map[string]struct{}, len(m.Blockers))
	for _, b := range m.Blockers {
		if err := requireEnum("blocker", b, mutationBlockers); err != nil {
			return err
		}
		if _, ok := seen[b]; ok {
			return fmt.Errorf("duplicate blocker %q", b)
		}
		seen[b] = struct{}{}
	}
	if m.Eligible && len(m.Blockers) > 0 {
		return fmt.Errorf("eligible=true must not set blockers")
	}
	return nil
}
