# Boot Doctor analysis (PR #19)

Status: **implemented as a library** in this PR. Not wired into WinPE GUI,
CLI startup, repair execution, or LLM Runtime v2.

## Purpose

Deterministic analysis only:

```text
Case Snapshot + WindowsBootTopology (+ typed read-only observations already stored)
→ Boot Doctor Findings
```

Boot Doctor **analyzes**. It does **not** repair, back up, roll back, approve,
or execute typed mutations.

## Package

`internal/recovery/bootdoctor`

Properties:

- Pure / deterministic
- No `os/exec`, network, filesystem mutation, or global state reads
- Injectable clock is not required (Findings carry no analysis timestamp field)
- Finding identity ignores wall-clock time
- Input/output types are explicit and validated

## Inputs

- Case identity
- Validated `WindowsBootTopology` (from PR #18 resolver / persisted Evidence)
- Snapshot Targets (for disk partition_style and ref checks)
- Known Evidence/Target ID sets (reject dangling refs)

## Outputs

Typed `Finding` documents (`finding` 1.0.0) with:

| Concern | Representation |
|---------|----------------|
| Finding code | First limitation `finding_code:<code>` (no schema bump) |
| Stable ID | `finding-` + SHA-256 prefix over case, code, targets, evidence |
| Severity | `info` / `low` / `medium` / `high` / `critical` |
| Confidence | domain `low` / `medium` / `high` (mapped from evidence quality) |
| Summary | `title` |
| Explanation | `rationale` |
| Evidence / targets | `evidence_refs`, `affected_target_ids` |
| Next diagnostic step | `recommended_workflows` containing typed **read-only** operation IDs only |
| Gaps | `insufficient_evidence=true` when refs are empty |

**No raw commands. No recovery passwords/keys.**

## Severity / confidence mapping (direction)

| Severity | Examples |
|----------|----------|
| critical | storage critical; proven cross-disk destructive-risk topology |
| high | locked BitLocker; missing Windows; firmware conflict; unknown storage/BitLocker treated unsafe |
| medium | missing/ambiguous ESP or BCD; incomplete topology |
| info | `boot_topology_consistent` |

| Domain confidence | When |
|-------------------|------|
| high | Direct blockers/ambiguities with strong topology proof |
| medium | Incomplete but directional signals |
| low | Unknown / insufficient evidence paths (`runtime_only` never promoted to proven) |

## Suppression / precedence

Documented in `suppress.go`:

1. Missing/ambiguous Windows suppresses secondary BCD-membership findings for that Windows.
2. Conflicting/unknown firmware suppresses `boot_topology_consistent` and layout certainty beyond the conflict finding.
3. BitLocker locked/unknown suppresses “healthy topology” and does not assert filesystem corruption.
4. Storage critical keeps other confirmed findings but forces `unsafe_to_attempt_boot_repair` and suppresses consistent.
5. Ambiguous/incomplete topology never silently selects a single target and never emits consistent.
6. Cross-disk ESP/BCD keeps critical unsafe-to-repair.

Absence of Findings must **not** be interpreted as healthy. The informational
`boot_topology_consistent` Finding is emitted only when eligibility, uniqueness,
relations, firmware, BitLocker, and storage checks all pass.

## Coordinator integration

`Coordinator.CommitBootDoctorAnalysis`:

1. Verify Case Store integrity (corrupt head blocks analysis)
2. Select persisted `windows-boot-topology` Evidence
3. Run `bootdoctor.Analyze`
4. Append immutable Findings via existing `CommitAnalysis` authority
5. Emit `analysis_committed` audit event
6. Advance `evidence_collected → analyzed` when invariants allow

Idempotency: identical `request_id` (`acqreq-*`) with identical Finding set
replays without a second divergent commit. Divergent reuse conflicts.
Optimistic concurrency still applies for new request IDs.

## Explicit non-goals

- Repair execution (`bcdboot`, `bootrec`, `diskpart`, `manage-bde`, shell)
- Planner / Policy Engine / Approval
- Backup / rollback
- LLM Runtime v2 / gateway authority
- GUI / WinPE startup integration
- Live reinspection beyond the PR #18 read registry
- Treating `mutation_eligibility.eligible=true` as approval

## Threat model (delta)

- Analyzer cannot invent mutation authority
- Findings cannot carry command-like fields
- BitLocker secrets must never appear in Findings, fixtures, or logs
- Corrupt Case Store fails closed
- Ambiguous topology cannot become silently eligible via Boot Doctor

## Rollback

Revert the PR #19 branch / close the Draft PR. Case Store on-disk format for
Findings is unchanged from PR #17; Boot Doctor only produces standard Finding
documents.
