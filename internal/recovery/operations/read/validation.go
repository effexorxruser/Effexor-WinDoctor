package read

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/evidenceview"
)

type handlerFunc func(context.Context, execContext) (domain.ReadOperationResult, error)

type execContext struct {
	request   Request
	target    domain.Target
	params    map[string]any
	index     *snapshotIndex
	verifier  StoreVerifier
	operation domain.OperationDescriptor
}

type snapshotIndex struct {
	targets         map[string]domain.Target
	bundlesByTarget map[string][]domain.EvidenceBundle
	evidenceByID    map[string]domain.EvidenceBundle
	views           map[string]evidenceview.View
	byType          map[string][]domain.Target
}

func buildSnapshotIndex(snap casestore.Snapshot) (*snapshotIndex, error) {
	idx := &snapshotIndex{
		targets:         make(map[string]domain.Target, len(snap.Targets)),
		bundlesByTarget: make(map[string][]domain.EvidenceBundle),
		evidenceByID:    make(map[string]domain.EvidenceBundle, len(snap.EvidenceBundles)),
		views:           make(map[string]evidenceview.View),
		byType:          make(map[string][]domain.Target),
	}
	for _, t := range snap.Targets {
		idx.targets[t.TargetID] = t
		idx.byType[t.TargetType] = append(idx.byType[t.TargetType], t)
	}
	for _, b := range snap.EvidenceBundles {
		idx.evidenceByID[b.EvidenceID] = b
		idx.bundlesByTarget[b.TargetID] = append(idx.bundlesByTarget[b.TargetID], b)
		view, err := evidenceview.DecodeBundle(b)
		if err != nil {
			if isUnsupportedEvidence(err) {
				continue
			}
			return nil, fmt.Errorf("evidence %s: %w", b.EvidenceID, err)
		}
		idx.views[b.EvidenceID] = view
	}
	for typ := range idx.byType {
		sort.Slice(idx.byType[typ], func(i, j int) bool {
			return idx.byType[typ][i].TargetID < idx.byType[typ][j].TargetID
		})
	}
	return idx, nil
}

func isUnsupportedEvidence(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unsupported facts schema")
}

func validateExecuteRequest(req Request, entry registryEntry) (domain.Target, map[string]any, error) {
	if err := req.ReadOperationRequest.Validate(); err != nil {
		return domain.Target{}, nil, fmt.Errorf("%w: %v", ErrMalformedParameters, err)
	}
	if req.CaseID != req.Snapshot.Case.CaseID {
		return domain.Target{}, nil, ErrCaseMismatch
	}
	if req.OperationVersion != entry.descriptor.Version {
		return domain.Target{}, nil, ErrUnknownVersion
	}
	target, ok := findTarget(req.Snapshot.Targets, req.TargetID)
	if !ok {
		return domain.Target{}, nil, ErrTargetNotFound
	}
	if !supportsTargetType(entry.targetTypes, target.TargetType) {
		return domain.Target{}, nil, fmt.Errorf("%w: %q", ErrUnsupportedTargetType, target.TargetType)
	}
	params, err := decodeParameters(req.Parameters)
	if err != nil {
		return domain.Target{}, nil, err
	}
	if err := validateParametersForOperation(req.OperationID, params); err != nil {
		return domain.Target{}, nil, err
	}
	return target, params, nil
}

func decodeParameters(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: parameters is required", ErrMalformedParameters)
	}
	var params map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&params); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedParameters, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: trailing JSON content", ErrMalformedParameters)
		}
		return nil, fmt.Errorf("%w: %v", ErrMalformedParameters, err)
	}
	return params, nil
}

func validateParametersForOperation(operationID string, params map[string]any) error {
	forbidden := []string{"command", "shell", "powershell", "argv", "executable", "script"}
	for _, key := range forbidden {
		if _, ok := params[key]; ok {
			return fmt.Errorf("%w: forbidden field %q", ErrMalformedParameters, key)
		}
	}
	switch operationID {
	case "boot.inspect_efi_layout", "storage.inspect_partition_layout":
		for k := range params {
			if k != "disk_target_id" {
				return fmt.Errorf("%w: unknown parameter %q", ErrUnknownParameter, k)
			}
		}
		if v, ok := params["disk_target_id"]; ok {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("%w: disk_target_id must be a string", ErrMalformedParameters)
			}
			if s == "" {
				return fmt.Errorf("%w: disk_target_id must not be empty", ErrMalformedParameters)
			}
		}
	default:
		if len(params) != 0 {
			return fmt.Errorf("%w: parameters must be empty for operation %q", ErrMalformedParameters, operationID)
		}
	}
	return nil
}

func validateResultAgainstRequest(req Request, result domain.ReadOperationResult) error {
	if result.RequestID != req.RequestID ||
		result.CaseID != req.CaseID ||
		result.OperationID != req.OperationID ||
		result.OperationVersion != req.OperationVersion ||
		result.TargetID != req.TargetID {
		return ErrResultMismatch
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrResultMismatch, err)
	}
	return nil
}

func validateSourceEvidence(result domain.ReadOperationResult, idx *snapshotIndex) error {
	for _, id := range result.SourceEvidenceIDs {
		if _, ok := idx.evidenceByID[id]; !ok {
			return fmt.Errorf("%w: %q", ErrUnresolvedEvidence, id)
		}
	}
	return nil
}

func validateDescriptor(desc domain.OperationDescriptor, targetTypes []string, handler handlerFunc) error {
	if desc.RiskClass != domain.RiskReadOnly {
		return fmt.Errorf("%w: only read_only operations are supported", ErrInvalidDescriptor)
	}
	if desc.MutationClass != "none" {
		return fmt.Errorf("%w: mutation_class must be none", ErrInvalidDescriptor)
	}
	if desc.RequiresBackup {
		return fmt.Errorf("%w: requires_backup must be false", ErrInvalidDescriptor)
	}
	if desc.RequiresExplicitApproval {
		return fmt.Errorf("%w: requires_explicit_approval must be false", ErrInvalidDescriptor)
	}
	if err := desc.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDescriptor, err)
	}
	if desc.ParametersSchemaRef == "" || desc.ResultSchemaRef == "" {
		return fmt.Errorf("%w: schema refs are required", ErrInvalidDescriptor)
	}
	if len(targetTypes) == 0 {
		return ErrUndefinedTargetType
	}
	if handler == nil {
		return ErrMissingHandler
	}
	return nil
}

func supportsTargetType(allowed []string, targetType string) bool {
	for _, t := range allowed {
		if t == targetType {
			return true
		}
	}
	return false
}

func findTarget(targets []domain.Target, targetID string) (domain.Target, bool) {
	for _, t := range targets {
		if t.TargetID == targetID {
			return t, true
		}
	}
	return domain.Target{}, false
}

func diskTargetID(params map[string]any) string {
	if params == nil {
		return ""
	}
	v, ok := params["disk_target_id"]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func observedAtFromEvidence(ids []string, idx *snapshotIndex, fallback string) string {
	var latest time.Time
	for _, id := range ids {
		b, ok := idx.evidenceByID[id]
		if !ok {
			continue
		}
		ts, err := time.Parse(time.RFC3339, b.CapturedAt)
		if err != nil {
			continue
		}
		if latest.IsZero() || ts.After(latest) {
			latest = ts
		}
	}
	if !latest.IsZero() {
		return latest.UTC().Format(time.RFC3339)
	}
	if fallback != "" {
		return fallback
	}
	return time.Unix(0, 0).UTC().Format(time.RFC3339)
}

func baseResult(req Request, source domain.ObservationSource, status domain.ReadObservationStatus, evidenceIDs []string, limitations []string) domain.ReadOperationResult {
	if evidenceIDs == nil {
		evidenceIDs = []string{}
	}
	if limitations == nil {
		limitations = []string{}
	}
	return domain.ReadOperationResult{
		SchemaName:        domain.SchemaReadOperationResult,
		SchemaVersion:     domain.SchemaVersion,
		RequestID:         req.RequestID,
		CaseID:            req.CaseID,
		OperationID:       req.OperationID,
		OperationVersion:  req.OperationVersion,
		TargetID:          req.TargetID,
		Status:            status,
		ObservationSource: source,
		SourceEvidenceIDs: sortedCopy(evidenceIDs),
		Limitations:       limitations,
	}
}

func mergeLimitations(base []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, v := range append(append([]string(nil), base...), extra...) {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (idx *snapshotIndex) viewsForTarget(targetID string) []evidenceview.View {
	out := make([]evidenceview.View, 0)
	for _, b := range idx.bundlesByTarget[targetID] {
		if view, ok := idx.views[b.EvidenceID]; ok {
			out = append(out, view)
		}
	}
	return out
}

func (idx *snapshotIndex) evidenceIDsForTarget(targetID string) []string {
	out := make([]string, 0, len(idx.bundlesByTarget[targetID]))
	for _, b := range idx.bundlesByTarget[targetID] {
		out = append(out, b.EvidenceID)
	}
	return sortedCopy(out)
}

func (idx *snapshotIndex) allBitLockerViews() []evidenceview.View {
	out := make([]evidenceview.View, 0)
	for _, view := range idx.views {
		if view.EntityKind == "bitlocker_volume" {
			out = append(out, view)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Bundle.EvidenceID < out[j].Bundle.EvidenceID
	})
	return out
}

func (idx *snapshotIndex) partitionsOnDisk(diskID string) []domain.Target {
	diskNumber := diskNumberForTarget(idx, diskID)
	out := make([]domain.Target, 0)
	for _, t := range idx.byType["partition"] {
		if partitionOnDisk(idx, t.TargetID, diskID, diskNumber) {
			out = append(out, t)
		}
	}
	return out
}

func partitionOnDisk(idx *snapshotIndex, partitionID, diskID string, diskNumber *int64) bool {
	for _, view := range idx.viewsForTarget(partitionID) {
		for _, rel := range view.RelatedTargetIDs {
			if rel == diskID {
				return true
			}
		}
		part, err := view.Partition()
		if err == nil && diskNumber != nil && part.DiskNumber != nil && *part.DiskNumber == *diskNumber {
			return true
		}
	}
	return false
}

func diskNumberForTarget(idx *snapshotIndex, diskID string) *int64 {
	for _, view := range idx.viewsForTarget(diskID) {
		disk, err := view.Disk()
		if err == nil && disk.DiskNumber != nil {
			n := *disk.DiskNumber
			return &n
		}
	}
	if t, ok := idx.targets[diskID]; ok {
		if n, ok := parseLocatorInt(t.RuntimeLocators, "disk_number"); ok {
			return &n
		}
	}
	return nil
}

func parseLocatorInt(loc map[string]string, key string) (int64, bool) {
	if loc == nil {
		return 0, false
	}
	s, ok := loc[key]
	if !ok {
		return 0, false
	}
	var n int64
	_, err := fmt.Sscan(s, &n)
	return n, err == nil
}

const espGPTTypeGUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

func normalizeGUID(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "{")
	v = strings.TrimSuffix(v, "}")
	return strings.ToLower(v)
}

func isESPPayload(view evidenceview.View) bool {
	part, err := view.Partition()
	if err != nil {
		return false
	}
	if normalizeGUID(part.GPTType) == espGPTTypeGUID {
		return true
	}
	joined := strings.ToUpper(part.Type)
	return strings.Contains(joined, "EFI") || strings.Contains(joined, "SYSTEM")
}
