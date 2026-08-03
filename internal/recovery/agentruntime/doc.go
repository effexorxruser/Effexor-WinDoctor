// Package agentruntime implements Recovery Agent Runtime v2: a provider-neutral
// bounded consultation loop over verified Recovery Cases, Boot Doctor Findings,
// and typed read-only Coordinator operations.
//
// The runtime never executes model command text, never creates RepairPlans,
// never grants approval, and never advances workflow past analyzed.
package agentruntime

import (
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/agentloop"
)

const (
	RuntimeID      = "effexor-recovery-agent-runtime"
	RuntimeVersion = "2.0.0"
	SchemaVersion  = "1.0.0"

	MaxRounds               = agentloop.MaxRounds
	MaxRequestBytes         = agentloop.MaxRequestBytes
	MaxResponseBytes        = agentloop.MaxResponseBytes
	MaxReadRequestsPerRound = 4
	MaxReadRequestsTotal    = agentloop.MaxEvidenceRequests
	MaxHypotheses           = 8
	MaxSources              = 16
	MaxAuditEvents          = agentloop.MaxAuditEvents
	MaxLimitations          = agentloop.MaxLimitations
	DefaultTimeout          = 90 * time.Second
	ProviderTimeout         = 30 * time.Second
	OperationTimeout        = 30 * time.Second
)

const (
	StatusCompleted         = "completed"
	StatusNeedsMoreEvidence = "needs_more_evidence"
	StatusBlocked           = "blocked"
	StatusFailed            = "failed"
)
