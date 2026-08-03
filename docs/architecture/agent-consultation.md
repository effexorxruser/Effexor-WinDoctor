# Agent Consultation 1.0.0

Advisory, model-authored enrichment of a Recovery Case.

## Contract

- Schema: `agent-consultation` / `1.0.0`
- Path: `contracts/recovery/agent-consultation-1.0.0/`
- IDs: `consult-<24 hex>`, request `creq-<24 hex>`, hypothesis `hyp-<24 hex>`

## Persistence

- Stored under Case Store `agent-consultations/{consultation_id}.json`
- Append-only; identical `request_id` retries are idempotent
- Divergent payload under the same `request_id` conflicts
- Identity ignores `generated_at`
- No CoordinatorEvent is emitted (acquisition-like enrichment)
- Workflow state/revision unchanged

## Statuses

`completed` | `needs_more_evidence` (runtime-internal) | `blocked` | `failed`

Terminal persisted statuses are `completed`, `blocked`, or `failed`.

## Safety

- Not a Finding and not an approval
- Must not contain raw command/argv/script fields
- Retrieved sources must be HTTPS and provider-returned
- BitLocker recovery material must never appear in serialized documents
