package domain

import (
	"fmt"
	"strings"
)

// Target describes a stable recovery target. Drive letters are locators, not identity.
type Target struct {
	SchemaName      string            `json:"schema_name"`
	SchemaVersion   string            `json:"schema_version"`
	TargetID        string            `json:"target_id"`
	TargetType      string            `json:"target_type"`
	DiscoveredAt    string            `json:"discovered_at"`
	DisplayName     string            `json:"display_name"`
	StableIdentity  map[string]string `json:"stable_identity"`
	RuntimeLocators map[string]string `json:"runtime_locators"`
	Capabilities    []string          `json:"capabilities"`
	Limitations     []string          `json:"limitations"`
}

var targetTypes = map[string]struct{}{
	"disk":                 {},
	"partition":            {},
	"volume":               {},
	"windows_installation": {},
	"firmware":             {},
	"boot_store":           {},
}

func (t Target) Validate() error {
	if err := requireSchema(t.SchemaName, t.SchemaVersion, SchemaTarget); err != nil {
		return err
	}
	if err := requireMatch("target_id", t.TargetID, reTargetID); err != nil {
		return err
	}
	if err := requireEnum("target_type", t.TargetType, targetTypes); err != nil {
		return err
	}
	if err := requireRFC3339("discovered_at", t.DiscoveredAt); err != nil {
		return err
	}
	if err := requireNonEmpty("display_name", t.DisplayName); err != nil {
		return err
	}
	if t.StableIdentity == nil || len(t.StableIdentity) == 0 {
		return fmt.Errorf("stable_identity must contain at least one field")
	}
	for k, v := range t.StableIdentity {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("stable_identity entries must be non-empty")
		}
	}
	if t.RuntimeLocators == nil {
		return fmt.Errorf("runtime_locators is required")
	}
	if t.Capabilities == nil {
		return fmt.Errorf("capabilities is required")
	}
	if t.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	return nil
}
