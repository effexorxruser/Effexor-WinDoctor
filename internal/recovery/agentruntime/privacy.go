package agentruntime

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	PrivacyMachineInventory    = "machine_inventory"
	PrivacyBootConfiguration   = "boot_configuration"
	PrivacyStorageHealth       = "storage_health"
	PrivacyEncryptionStatus    = "encryption_status"
	PrivacyFilesystemMetadata  = "filesystem_metadata"
	PrivacyNetworkStatus       = "network_status"
	PrivacyTechnicianNotes     = "technician_notes"
	PrivacyCustomerIdentifying = "customer_identifying"
)

// PrivacyPolicy is an allowlist-based privacy class policy.
type PrivacyPolicy struct {
	Class            string
	AllowedKeys      map[string]struct{}
	ForbiddenKeys    map[string]struct{}
	UploadAllowed    bool
	LocalOnly        bool
	RequiresApproval bool
}

var privacyPolicies = map[string]PrivacyPolicy{
	PrivacyMachineInventory: {
		Class: PrivacyMachineInventory,
		ForbiddenKeys: map[string]struct{}{
			"hostname": {}, "username": {}, "sid": {}, "serial_number": {},
		},
		UploadAllowed: true,
	},
	PrivacyBootConfiguration: {
		Class: PrivacyBootConfiguration,
		ForbiddenKeys: map[string]struct{}{
			"hostname": {}, "username": {},
		},
		UploadAllowed: true,
	},
	PrivacyStorageHealth: {
		Class: PrivacyStorageHealth,
		ForbiddenKeys: map[string]struct{}{
			"serial_number": {}, "hostname": {},
		},
		UploadAllowed: true,
	},
	PrivacyEncryptionStatus: {
		Class: PrivacyEncryptionStatus,
		ForbiddenKeys: map[string]struct{}{
			"recovery_key": {}, "recovery_password": {}, "password": {},
			"protector_id": {}, "hostname": {},
		},
		UploadAllowed:    false,
		LocalOnly:        true,
		RequiresApproval: true,
	},
	PrivacyFilesystemMetadata: {
		Class: PrivacyFilesystemMetadata,
		ForbiddenKeys: map[string]struct{}{
			"username": {}, "user_profile": {}, "home_path": {},
		},
		UploadAllowed: true,
	},
	PrivacyNetworkStatus: {
		Class: PrivacyNetworkStatus,
		ForbiddenKeys: map[string]struct{}{
			"ssid": {}, "mac_address": {}, "hostname": {}, "ip_address": {},
		},
		UploadAllowed: true,
	},
	PrivacyTechnicianNotes: {
		Class:         PrivacyTechnicianNotes,
		UploadAllowed: false,
		LocalOnly:     true,
	},
	PrivacyCustomerIdentifying: {
		Class: PrivacyCustomerIdentifying,
		ForbiddenKeys: map[string]struct{}{
			"customer_name": {}, "email": {}, "phone": {}, "address": {},
		},
		UploadAllowed: false,
		LocalOnly:     true,
	},
}

var secretKeyFragments = []string{
	"recovery_key", "recovery_password", "password", "secret", "token",
	"credential", "api_key", "private_key",
}

// PolicyFor returns the closed privacy policy for a class.
func PolicyFor(class string) PrivacyPolicy {
	if p, ok := privacyPolicies[class]; ok {
		return p
	}
	return PrivacyPolicy{
		Class:         class,
		UploadAllowed: false,
		LocalOnly:     true,
		ForbiddenKeys: map[string]struct{}{},
	}
}

// MayUpload reports whether facts from this class may enter the next provider round.
func MayUpload(class string) bool {
	p := PolicyFor(class)
	return p.UploadAllowed && !p.LocalOnly && !p.RequiresApproval
}

func (p PrivacyPolicy) IsForbiddenKey(key string) bool {
	if _, ok := p.ForbiddenKeys[key]; ok {
		return true
	}
	for _, frag := range secretKeyFragments {
		if strings.Contains(key, frag) {
			return true
		}
	}
	return false
}

func privacyClassForFactsSchema(schema string) string {
	switch {
	case strings.Contains(schema, "bitlocker"):
		return PrivacyEncryptionStatus
	case strings.Contains(schema, "boot") || strings.Contains(schema, "bcd") || strings.Contains(schema, "firmware") || strings.Contains(schema, "topology"):
		return PrivacyBootConfiguration
	case strings.Contains(schema, "disk") || strings.Contains(schema, "storage") || strings.Contains(schema, "partition"):
		return PrivacyStorageHealth
	case strings.Contains(schema, "network"):
		return PrivacyNetworkStatus
	case strings.Contains(schema, "windows") || strings.Contains(schema, "install"):
		return PrivacyMachineInventory
	default:
		return PrivacyFilesystemMetadata
	}
}

func containsSecretValue(v any) bool {
	switch t := v.(type) {
	case string:
		lower := strings.ToLower(t)
		if strings.Contains(lower, "recovery key") || strings.Contains(lower, "bitlocker recovery") {
			return true
		}
		if looksLikeSecretToken(t) {
			return true
		}
	case map[string]any:
		for k, child := range t {
			if PolicyFor("").IsForbiddenKey(strings.ToLower(k)) || containsSecretValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if containsSecretValue(child) {
				return true
			}
		}
	}
	return false
}

func looksLikeSecretToken(s string) bool {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) >= 32 && strings.Count(trimmed, "-") >= 4 {
		// BitLocker-like recovery key pattern
		parts := strings.Split(trimmed, "-")
		if len(parts) == 8 {
			return true
		}
	}
	return false
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			lk := strings.ToLower(k)
			if PolicyFor("").IsForbiddenKey(lk) || containsSecretValue(child) {
				continue
			}
			out[k] = redactValue(child)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, child := range t {
			if containsSecretValue(child) {
				continue
			}
			out = append(out, redactValue(child))
		}
		return out
	default:
		return v
	}
}

// ValidateHTTPSSource enforces HTTPS-only retrieved sources without credentials.
func ValidateHTTPSSource(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid source url: %w", err)
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("source url must be https")
	}
	if u.User != nil {
		return "", "", fmt.Errorf("source url must not contain credentials")
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("source url host is required")
	}
	host := strings.ToLower(u.Hostname())
	normalized := "https://" + u.Host + u.EscapedPath()
	if u.RawQuery != "" {
		normalized += "?" + u.RawQuery
	}
	return normalized, host, nil
}
