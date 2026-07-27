# ADR 0002: Local authority

- Status: accepted (documentation)
- Date: 2026-07-27

## Context

Optional model-backed assistance is valuable, but provider-side or gateway-side
authority over on-device mutation would violate the project’s safety model and
`AGENTS.md` invariants.

## Decision

**Local authority is absolute for execution.**

- Only on-device policy plus technician **Approval** may authorize operations.
- **Effexor Recovery Gateway** may return findings, sources, and *proposed*
  typed operations.
- The gateway, model provider, and any remote hub have **no local authority**.
- UI and CLI may request actions; they cannot bypass policy.
- Collectors remain read-only. Analyzers / preflight logic cannot execute
  mutating operations.

## Consequences

- Gateway features stay advisory even when highly trusted.
- Device tokens authenticate gateway access; they do not grant repair rights.
- Future mutation work must implement local approval and audit, not remote push
  execution.
