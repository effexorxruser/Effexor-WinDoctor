# ADR 0004: Evidence before action

- Status: accepted (documentation)
- Date: 2026-07-27

## Context

Repair without grounded evidence causes irreversible damage and false
confidence. Missing data must not be treated as proof of health.

## Decision

The platform recovery loop is:

**Evidence → Finding → Hypothesis → Plan → Approval → Backup → Operation →
Verification → Rollback / Completion.**

Rules:

- Findings and hypotheses must cite evidence or explicitly state gaps.
- Plans are derived from typed steps, not improvisation.
- **Mutation without verification is incomplete.**
- Backup (when applicable) precedes mutating operations.
- Rollback path or explicit completion closes the loop.

Present implementation covers collection and conservative offline/gateway
findings. Backup, mutation, verification orchestration, and case completion
workflows are **future work**.

## Consequences

- Boot Doctor and later verticals must implement the loop, not shortcuts.
- Eval and CI should punish invented evidence paths (already gateway posture).
- Documentation must keep “implemented” vs “target loop” distinct.
