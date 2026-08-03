package agentruntime

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/agentloop"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	readops "github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/read"
)

// AuthorizedReadRequest is a locally authorized typed read proposal.
type AuthorizedReadRequest struct {
	RequestKey       string
	OperationID      string
	OperationVersion string
	TargetID         string
	Parameters       json.RawMessage
	Descriptor       domain.OperationDescriptor
}

// AuthorizeReadRequests validates provider read proposals against the local registry.
func AuthorizeReadRequests(
	snap casestore.Snapshot,
	registry *readops.Registry,
	requests []ReadRequestDraft,
	priorKeys map[string]struct{},
	remainingBudget int,
) ([]AuthorizedReadRequest, error) {
	if registry == nil {
		return nil, fmt.Errorf("read operation registry is required")
	}
	if len(requests) > MaxReadRequestsPerRound {
		return nil, fmt.Errorf("too many read_requests in round (max %d)", MaxReadRequestsPerRound)
	}
	if len(requests) > remainingBudget {
		return nil, fmt.Errorf("read request budget exceeded")
	}
	targets := map[string]domain.Target{}
	for _, t := range snap.Targets {
		targets[t.TargetID] = t
	}
	out := make([]AuthorizedReadRequest, 0, len(requests))
	seenKeys := map[string]struct{}{}
	for i, req := range requests {
		key := strings.TrimSpace(req.RequestKey)
		if key == "" {
			return nil, fmt.Errorf("read_requests[%d].request_key is required", i)
		}
		if _, dup := seenKeys[key]; dup {
			return nil, fmt.Errorf("duplicate read request_key %q in round", key)
		}
		seenKeys[key] = struct{}{}
		if _, dup := priorKeys[key]; dup {
			return nil, fmt.Errorf("duplicate read request_key %q", key)
		}
		if req.OperationID == "" || req.OperationVersion == "" || req.TargetID == "" {
			return nil, fmt.Errorf("read_requests[%d] missing operation/target fields", i)
		}
		desc, ok := registry.Descriptor(req.OperationID, req.OperationVersion)
		if !ok {
			return nil, fmt.Errorf("unknown operation %s@%s", req.OperationID, req.OperationVersion)
		}
		if desc.RiskClass != domain.RiskReadOnly {
			return nil, fmt.Errorf("operation %s is not read_only", req.OperationID)
		}
		if desc.MutationClass != "none" {
			return nil, fmt.Errorf("operation %s mutation_class must be none", req.OperationID)
		}
		target, ok := targets[req.TargetID]
		if !ok {
			return nil, fmt.Errorf("target_id %q is not in case", req.TargetID)
		}
		_ = target
		params := req.Parameters
		if len(params) == 0 {
			params = json.RawMessage(`{}`)
		}
		if len(params) > 16<<10 {
			return nil, fmt.Errorf("read_requests[%d].parameters too large", i)
		}
		if err := rejectCommandBearingJSON(fmt.Sprintf("read_requests[%d].parameters", i), params); err != nil {
			return nil, err
		}
		if err := agentloop.RejectCommandText(fmt.Sprintf("read_requests[%d].operation_id", i), req.OperationID); err != nil {
			// Operation IDs are dotted identifiers; RejectCommandText should allow them.
			// Still keep defense for unexpected payloads.
			if strings.Contains(req.OperationID, " ") || strings.Contains(req.OperationID, "/") {
				return nil, err
			}
		}
		out = append(out, AuthorizedReadRequest{
			RequestKey:       key,
			OperationID:      req.OperationID,
			OperationVersion: req.OperationVersion,
			TargetID:         req.TargetID,
			Parameters:       params,
			Descriptor:       desc,
		})
	}
	return out, nil
}

func rejectCommandBearingJSON(field string, raw json.RawMessage) error {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%s must be a JSON object", field)
	}
	forbiddenFields := []string{
		"command", "argv", "args", "script", "powershell", "executable",
		"shell", "cmdline", "cmd", "body", "download_url",
	}
	for k, v := range obj {
		lk := strings.ToLower(k)
		for _, f := range forbiddenFields {
			if lk == f {
				return fmt.Errorf("%s contains forbidden field %q", field, k)
			}
		}
		if s, ok := v.(string); ok {
			if err := agentloop.RejectCommandText(field+"."+k, s); err != nil {
				return err
			}
		}
	}
	return nil
}
