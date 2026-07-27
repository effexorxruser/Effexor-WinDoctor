# ADR 0003: Typed operations

- Status: accepted (documentation)
- Date: 2026-07-27

## Context

Unrestricted shell strings from a model or free-form UI are incompatible with
previewable, auditable recovery on client disks.

## Decision

All recoverable actions are **typed operations**:

- identified by a stable operation id / schema;
- carrying explicit preconditions, parameters, and expected effects;
- subject to policy checks before execution;
- distinguishable as read-only vs mutating.

**No raw model commands.** Model output may suggest typed operation ids and
parameters that the local policy understands; anything else is rejected.

Current gateway/preflight “next steps” that are read-only typed suggestions are
aligned with this direction. Mutating typed operations are **not implemented**
yet and must not be described as shipped.

## Consequences

- Contracts for operations will land in a later PR (roadmap R1+).
- UI shows previews derived from type metadata, not opaque scripts.
- Adding a new capability means adding a typed operation, not widening a shell
  escape hatch.
