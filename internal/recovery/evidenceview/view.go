// Package evidenceview provides read-only typed views over EvidenceBundle facts.
//
// It does not mutate EvidenceBundle documents and does not invent missing
// evidence. Unknown or malformed facts surface as typed errors.
package evidenceview

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

var (
	// ErrUnsupportedSchema indicates FactsSchema is not a known view schema.
	ErrUnsupportedSchema = errors.New("evidenceview: unsupported facts schema")
	// ErrMalformedEvidence indicates facts bytes failed strict decoding.
	ErrMalformedEvidence = errors.New("evidenceview: malformed evidence")
)

// View is a read-only decoded facts view for one EvidenceBundle.
type View struct {
	Bundle           domain.EvidenceBundle
	FactsSchema      string
	EntityKind       string
	RelatedTargetIDs []string
	Limitations      []string
	Envelope         legacyreport.FactsEnvelope
	Unsupported      bool
}

// DecodeBundle strictly decodes known legacy facts schemas.
func DecodeBundle(bundle domain.EvidenceBundle) (View, error) {
	view := View{
		Bundle:      bundle,
		FactsSchema: bundle.FactsSchema,
	}
	if !isLegacyFactsSchema(bundle.FactsSchema) {
		view.Unsupported = true
		return view, fmt.Errorf("%w: %q", ErrUnsupportedSchema, bundle.FactsSchema)
	}
	env, err := legacyreport.DecodeFactsEnvelopeStrict(bundle.Facts)
	if err != nil {
		return View{}, fmt.Errorf("%w: %v", ErrMalformedEvidence, err)
	}
	view.Envelope = env
	view.EntityKind = env.EntityKind
	view.RelatedTargetIDs = append([]string(nil), env.RelatedTargetIDs...)
	view.Limitations = append([]string(nil), env.Limitations...)
	view.Limitations = appendUnique(view.Limitations, bundle.Limitations...)
	return view, nil
}

func isLegacyFactsSchema(schema string) bool {
	if schema == legacyreport.FactsSchemaID {
		return true
	}
	return strings.Contains(schema, "legacy-diagnostic-report-fragment")
}

// FirmwarePayload extracts firmware_environment payload fields when present.
type FirmwarePayload struct {
	BootFirmwareMode     string
	HardwareFirmwareMode string
	Raw                  json.RawMessage
}

func (v View) Firmware() (FirmwarePayload, error) {
	if v.EntityKind != "firmware_environment" {
		return FirmwarePayload{}, fmt.Errorf("%w: entity_kind %q is not firmware_environment", ErrMalformedEvidence, v.EntityKind)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return FirmwarePayload{}, err
	}
	out := FirmwarePayload{Raw: append(json.RawMessage(nil), v.Envelope.Payload...)}
	if mode, ok := payload["boot_firmware_mode"].(string); ok {
		out.BootFirmwareMode = mode
	}
	if hw, ok := payload["hardware"].(map[string]any); ok {
		if mode, ok := hw["firmware_mode"].(string); ok {
			out.HardwareFirmwareMode = mode
		}
	}
	return out, nil
}

// DiskPayload is a typed disk facts view.
type DiskPayload struct {
	DiskNumber     *int64
	PartitionStyle string
	Raw            json.RawMessage
}

func (v View) Disk() (DiskPayload, error) {
	if v.EntityKind != "disk" {
		return DiskPayload{}, fmt.Errorf("%w: entity_kind %q is not disk", ErrMalformedEvidence, v.EntityKind)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return DiskPayload{}, err
	}
	out := DiskPayload{Raw: append(json.RawMessage(nil), v.Envelope.Payload...)}
	if n, ok := asInt64(payload["disk_number"]); ok {
		out.DiskNumber = &n
	}
	if s, ok := payload["partition_style"].(string); ok {
		out.PartitionStyle = s
	}
	return out, nil
}

// PartitionPayload is a typed partition facts view.
type PartitionPayload struct {
	DiskNumber  *int64
	DriveLetter string
	GPTType     string
	Type        string
	Raw         json.RawMessage
}

func (v View) Partition() (PartitionPayload, error) {
	if v.EntityKind != "partition" {
		return PartitionPayload{}, fmt.Errorf("%w: entity_kind %q is not partition", ErrMalformedEvidence, v.EntityKind)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return PartitionPayload{}, err
	}
	out := PartitionPayload{Raw: append(json.RawMessage(nil), v.Envelope.Payload...)}
	if n, ok := asInt64(payload["disk_number"]); ok {
		out.DiskNumber = &n
	}
	if s, ok := payload["drive_letter"].(string); ok {
		out.DriveLetter = s
	}
	if s, ok := payload["gpt_type"].(string); ok {
		out.GPTType = s
	}
	if s, ok := payload["type"].(string); ok {
		out.Type = s
	}
	if s, ok := payload["partition_type"].(string); ok && out.Type == "" {
		out.Type = s
	}
	return out, nil
}

// WindowsInstallationPayload is a typed Windows installation view.
type WindowsInstallationPayload struct {
	RootPath string
	Version  string
	Raw      json.RawMessage
}

func (v View) WindowsInstallation() (WindowsInstallationPayload, error) {
	if v.EntityKind != "windows_installation" {
		return WindowsInstallationPayload{}, fmt.Errorf("%w: entity_kind %q is not windows_installation", ErrMalformedEvidence, v.EntityKind)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return WindowsInstallationPayload{}, err
	}
	out := WindowsInstallationPayload{Raw: append(json.RawMessage(nil), v.Envelope.Payload...)}
	if s, ok := payload["root_path"].(string); ok {
		out.RootPath = s
	}
	if s, ok := payload["version"].(string); ok {
		out.Version = s
	}
	return out, nil
}

// BootStorePayload is a typed BCD/boot_store view.
type BootStorePayload struct {
	Kind string
	Path string
	Raw  json.RawMessage
}

func (v View) BootStore() (BootStorePayload, error) {
	if v.EntityKind != "boot_store" {
		return BootStorePayload{}, fmt.Errorf("%w: entity_kind %q is not boot_store", ErrMalformedEvidence, v.EntityKind)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return BootStorePayload{}, err
	}
	out := BootStorePayload{Raw: append(json.RawMessage(nil), v.Envelope.Payload...)}
	if s, ok := payload["kind"].(string); ok {
		out.Kind = s
	}
	if s, ok := payload["path"].(string); ok {
		out.Path = s
	}
	return out, nil
}

// BitLockerPayload is a typed BitLocker volume view.
type BitLockerPayload struct {
	ProtectionStatus string
	LockStatus       string
	MountPoint       string
	Raw              json.RawMessage
}

func (v View) BitLocker() (BitLockerPayload, error) {
	if v.EntityKind != "bitlocker_volume" {
		return BitLockerPayload{}, fmt.Errorf("%w: entity_kind %q is not bitlocker_volume", ErrMalformedEvidence, v.EntityKind)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return BitLockerPayload{}, err
	}
	out := BitLockerPayload{Raw: append(json.RawMessage(nil), v.Envelope.Payload...)}
	if s, ok := payload["protection_status"].(string); ok {
		out.ProtectionStatus = s
	}
	if s, ok := payload["lock_status"].(string); ok {
		out.LockStatus = s
	}
	if s, ok := payload["mount_point"].(string); ok {
		out.MountPoint = s
	}
	return out, nil
}

// DriveHealthRecords extracts drive_health entries from firmware payload when present.
func (v View) DriveHealthRecords() ([]map[string]any, error) {
	if v.EntityKind != "firmware_environment" {
		return nil, fmt.Errorf("%w: drive health is on firmware_environment facts", ErrMalformedEvidence)
	}
	var payload map[string]any
	if err := decodePayload(v.Envelope.Payload, &payload); err != nil {
		return nil, err
	}
	raw, ok := payload["drive_health"]
	if !ok || raw == nil {
		return []map[string]any{}, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: drive_health is not an array", ErrMalformedEvidence)
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: drive_health entry is not an object", ErrMalformedEvidence)
		}
		out = append(out, m)
	}
	return out, nil
}

func decodePayload(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedEvidence, err)
	}
	return nil
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func appendUnique(dst []string, values ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}
