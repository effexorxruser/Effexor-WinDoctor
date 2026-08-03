# Recovery Agent Runtime v2

Provider-neutral bounded consultation over Recovery Domain Cases.

## Data flow

```text
Verified Case Snapshot
+ Windows Boot Topology
+ deterministic Boot Doctor Findings
        ↓
Sanitized Recovery Context (allowlist)
        ↓
Bounded provider rounds (injected RoundProvider)
        ↓
Validated typed read-only evidence requests
        ↓
Local Coordinator.ExecuteReadOperation
        ↓
Additional immutable Evidence (snapshot-backed)
        ↓
Advisory Agent Consultation (append-only)
```

## Authority boundary

- Model proposals are never executed as commands.
- Read requests are authorized against the local `operations/read` registry.
- Persistence goes only through Coordinator (`CommitAgentConsultation`).
- Workflow remains `analyzed` (no `plan_proposed` / approval / execution).
- Topology blockers and `mutation_eligibility` are not writable by the provider.
- Hypotheses are advisory documents, never automatic Boot Doctor Findings.

## Package

`internal/recovery/agentruntime`

Reuses legacy `internal/agentloop` policy primitives (limits, `RejectCommandText`,
HTTPS/source ideas, privacy redaction patterns) without calling `Loop.Run` on
Case data and without binding Recovery to diagnostic-report/session types.

## Non-goals (this PR)

Planner, policy engine, explicit approval, backup/rollback, repair execution,
WinPE GUI integration, live Windows reinspection, release readiness.
