package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	reCaseID                = regexp.MustCompile(`^case-[a-f0-9]{24}$`)
	reTargetID              = regexp.MustCompile(`^target-[a-z0-9-]{8,64}$`)
	reEvidenceID            = regexp.MustCompile(`^evidence-[a-f0-9]{24}$`)
	reFindingID             = regexp.MustCompile(`^finding-[a-f0-9]{24}$`)
	rePlanID                = regexp.MustCompile(`^plan-[a-f0-9]{24}$`)
	reOperationID           = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,63}$`)
	reExecutionID           = regexp.MustCompile(`^exec-[a-f0-9]{24}$`)
	reVerificationID        = regexp.MustCompile(`^verify-[a-f0-9]{24}$`)
	reArtifactID            = regexp.MustCompile(`^artifact-[a-f0-9]{24}$`)
	reCoordinatorEventID    = regexp.MustCompile(`^cevt-[a-f0-9]{24}$`)
	reAcquisitionID         = regexp.MustCompile(`^acq-[a-f0-9]{24}$`)
	reAcquisitionRequestID  = regexp.MustCompile(`^acqreq-[a-f0-9]{24}$`)
	reTopologyID            = regexp.MustCompile(`^topology-[a-f0-9]{24}$`)
	reReadRequestID         = regexp.MustCompile(`^readreq-[a-f0-9]{24}$`)
	reConsultationID        = regexp.MustCompile(`^consult-[a-f0-9]{24}$`)
	reConsultationRequestID = regexp.MustCompile(`^creq-[a-f0-9]{24}$`)
	reHypothesisID          = regexp.MustCompile(`^hyp-[a-f0-9]{24}$`)
	rePolicyEvaluationID    = regexp.MustCompile(`^pol-[a-f0-9]{24}$`)
	rePolicyRequestID       = regexp.MustCompile(`^polreq-[a-f0-9]{24}$`)
	reRepairApprovalID      = regexp.MustCompile(`^appr-[a-f0-9]{24}$`)
	reApprovalRequestID     = regexp.MustCompile(`^apprreq-[a-f0-9]{24}$`)
	reTechnicianRef         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,127}$`)
	reProducerID            = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,127}$`)
	reCommitID              = regexp.MustCompile(`^commit-[a-f0-9]{24}$`)
	reSnapshotID            = regexp.MustCompile(`^snapshot-[a-f0-9]{24}$`)
	reReasonCode            = regexp.MustCompile(`^[a-z][a-z0-9_]{1,127}$`)
	reCommandID             = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	reSHA256                = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reSemver                = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

func requireNonEmpty(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func requireMatch(field, value string, re *regexp.Regexp) error {
	if err := requireNonEmpty(field, value); err != nil {
		return err
	}
	if !re.MatchString(value) {
		return fmt.Errorf("%s %q does not match required pattern", field, value)
	}
	return nil
}

func requireRFC3339(field, value string) error {
	if err := requireNonEmpty(field, value); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("%s must be RFC3339: %w", field, err)
	}
	return nil
}

func requireSHA256(field, value string) error {
	if err := requireNonEmpty(field, value); err != nil {
		return err
	}
	if !reSHA256.MatchString(value) {
		return fmt.Errorf("%s must be 64 hexadecimal characters", field)
	}
	return nil
}

func requireSchema(name, version, wantName string) error {
	if name != wantName {
		return fmt.Errorf("schema_name must be %q", wantName)
	}
	if version != SchemaVersion {
		return fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	return nil
}

func requireEnum(field, value string, allowed map[string]struct{}) error {
	if err := requireNonEmpty(field, value); err != nil {
		return err
	}
	if _, ok := allowed[value]; !ok {
		return fmt.Errorf("%s has unknown value %q", field, value)
	}
	return nil
}

func validateRelativePath(field, path string) error {
	if err := requireNonEmpty(field, path); err != nil {
		return err
	}
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		return fmt.Errorf("%s must not be absolute", field)
	}
	if len(path) >= 2 && path[1] == ':' {
		return fmt.Errorf("%s must not be absolute", field)
	}
	if strings.Contains(path, "../") || strings.Contains(path, `..\`) {
		return fmt.Errorf("%s must not contain path traversal", field)
	}
	if path == ".." || strings.HasPrefix(path, "../") || strings.HasPrefix(path, `..\`) {
		return fmt.Errorf("%s must not contain path traversal", field)
	}
	return nil
}

func requireUniqueIDList(field string, values []string, re *regexp.Regexp) error {
	if values == nil {
		return fmt.Errorf("%s is required", field)
	}
	seen := make(map[string]struct{}, len(values))
	for i, id := range values {
		if err := requireMatch(fmt.Sprintf("%s[%d]", field, i), id, re); err != nil {
			return err
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%s contains duplicate %q", field, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func forbiddenKeys(raw map[string]any, keys ...string) error {
	for _, key := range keys {
		if _, ok := raw[key]; ok {
			return fmt.Errorf("forbidden field %q is not allowed", key)
		}
	}
	return nil
}
