# Recovery Case Store

Local crash-consistent persistence for Effexor Recovery Platform case
documents and artifact bytes.

Package: `internal/recovery/casestore`.

This module persists Recovery Domain documents and artifacts. It does **not**
make policy decisions, execute operations, or integrate into the current WinPE
runtime or GUI. Orchestration belongs to the Recovery Coordinator
([`recovery-coordinator.md`](recovery-coordinator.md)).

## Purpose

- Persist `CaseManifest`, `Target[]`, and `EvidenceBundle[]`
- Persist `Finding[]`, `RepairPlan[]`, `ExecutionEvent[]`, `VerificationReport[]`
- Persist optional `case-workflow-state` and `coordinator-event[]` documents
- Persist related artifact bytes
- Publish new case state atomically
- Load the latest committed state
- Verify hashes, sizes, references, and the commit chain
- Survive interrupted writes safely
- Support idempotent retry
- Explicit `ParentExpectation` on Commit: unspecified, specific parent, or absent head

## Recommended roots

The library never hard-codes a drive letter. Callers pass an explicit root:

| Profile | Recommended root |
|---------|------------------|
| WinPE working storage | `X:\EffexorRecovery\work` |
| Persistent technician storage | `<selected-drive>\EffexorRecovery` |

All staging and final renames stay inside one store root / filesystem.

## Directory layout

```text
<root>/
└── cases/
    └── <case_id>/
        ├── snapshots/
        │   └── <snapshot_id>/
        │       ├── snapshot-manifest.json
        │       └── documents/
        │           ├── case-manifest.json
        │           ├── case-workflow-state.json          (optional)
        │           ├── targets/<target_id>.json
        │           ├── evidence/<evidence_id>.json
        │           ├── findings/<finding_id>.json
        │           ├── plans/<plan_id>.json
        │           ├── executions/<execution_id>.json
        │           ├── verifications/<verification_id>.json
        │           └── coordinator-events/<event_id>.json
        ├── artifacts/sha256/<prefix>/<sha256>
        ├── commits/%020d-<commit_id>.json
        ├── staging/
        └── case.lock
```

There is **no** mutable `CURRENT.json`. The highest valid append-only commit
record is the current state.

Snapshots that contain only the original Case/Target/Evidence documents remain
readable. Empty new collections omit document files and normalize
deterministically. Lifecycle documents (`Findings`, `RepairPlans`,
`ExecutionEvents`, `VerificationReports`, `CoordinatorEvents`) are valid only
when `case-workflow-state` is present.

PR #17 additionally requires:

- create/adopt audit events reference the exact Case + workflow + all Target +
  all Evidence IDs of the snapshot;
- every Finding / RepairPlan has provenance in the matching analysis/plan audit
  event type;
- `ExecutionEvent` / `VerificationReport` documents are rejected until later
  workflow transitions exist;
- workflow `occurred_at` ordering compares parsed RFC3339 instants (equal
  timestamps allowed; lexical string order is not authoritative).

## Immutable snapshots

A `Snapshot` is the in-memory unit of persistence. On commit it becomes an
immutable on-disk directory addressed by:

`snapshot-<first 24 hex of content_sha256>`

`content_sha256` is computed from the canonical manifest body **without**
`snapshot_id` and `content_sha256`. Document entries are sorted by relative
path. Serialization uses compact `encoding/json` (deterministic map keys).
Snapshot-manifest schema version remains `1.0.0`; additional document path
classes are additive and backward compatible.

## Append-only commits

Each commit record is simultaneously:

- the commit marker
- current-state history
- audit metadata for snapshot commits

Filename: `%020d-<commit_id>.json`

Rules:

- sequence starts at 1 and increments by 1
- `parent_commit_id` matches the previous commit (null for the first)
- no gaps
- filename must match record content
- snapshot must exist and manifest hash must match
- **final commit rename is the only commit point**

The commit chain is **tamper-evident** for accidental damage and incomplete
writes. Without signatures it is **not tamper-proof** against an attacker who
can rewrite the entire history on disk.

## Atomic commit algorithm

Under an exclusive case lock:

1. Validate snapshot and prepare artifacts
2. Load/verify current commit chain
3. Build deterministic documents + snapshot manifest
4. If `snapshot_id` is already head → return idempotent `CommitInfo`
5. Create a fresh staging transaction directory via exclusive `txn-*` mkdir
6. Stage documents and artifacts; sync after each write
7. Sync newly created managed directories before they can contain committed data
8. Publish snapshot via same-filesystem rename
9. Write commit record to a temp file, sync, rename to final name
10. Sync commits directory: Unix hard-error before returning success; Windows best-effort warning in `CommitInfo`
11. Unlock and return

Until the commit rename, the new state is not committed. After the rename,
a directory flush failure yields `CommitOutcomeUnknownError`; retrying the
same snapshot remains safe and idempotent. Previous committed snapshots are
never deleted during Commit.

## Artifact storage

Store **never** opens `ArtifactRef.relative_path`. Bytes arrive only through
`ArtifactProvider`. Blobs are content-addressed:

`artifacts/sha256/<first-two-hex>/<full-sha256>`

Streaming copy verifies SHA-256 and size against the ref. Orphan blobs after
crash are allowed and are not treated as committed.

## Locking

Interprocess exclusive lock via `case.lock`:

- Windows: `CreateFile` with share mode 0; handle held for the operation
- Unix: `flock` exclusive

Busy lock → `ErrCaseLocked`. The lock file is not deleted on unlock (avoids
create/delete races). Crash releases the OS lock automatically.

## Load and verify

`LoadLatest` reads only final commit records, validates the chain, verifies
manifest/document/artifact hashes and sizes, strict-decodes domain documents,
and runs `Snapshot.Validate()`. Staging, temps, and orphan snapshots are
ignored.

Corrupted **latest** committed state returns an integrity error with last
known valid commit information. There is **no** silent fallback to an older
commit (that would hide data loss).

`Verify` is read-only and reports staging/orphans/temps/warnings/errors with
status `ok` | `degraded` | `corrupt`.

## Recovery inspection and cleanup

`InspectRecovery` is read-only classification of committed, staging, temp,
orphan, and malformed objects.

`CleanupStaging` requires exclusive lock and removes **only**:

- non-reparse staging transaction directories named `txn-*`
- temporary files with the reserved store suffix

It does **not** auto-delete committed snapshots, orphan published snapshots,
content-addressed artifacts, malformed final commits, arbitrary staging files,
or generic `.tmp` files.

## Durability limitations

Directory sync behavior is platform-specific:

- Unix: directory sync failures are hard errors and block commit success before
  the commit marker is reported as durable
- Windows: directory sync is best-effort and warnings are surfaced in
  `CommitInfo`

FAT/exFAT, removable media, and write-cached controllers may still lose
recently published metadata after power loss even when file contents were
synced. Warnings are surfaced; they are never silent successes.

## Validation status

The package is exercised in normal and race CI, including the GitHub race job.

## Threat model

In scope: crash consistency, incomplete writes, accidental corruption,
idempotent retry, path traversal / symlink rejection.

Out of scope: an attacker with full rewrite access to the store filesystem;
network/cloud storage; signed commit history.

## What the coordinator consumes

The Recovery Coordinator ([`recovery-coordinator.md`](recovery-coordinator.md)):

- calls `Commit` after importer / analysis / plan commits
- calls `LoadLatest` to resume cases
- uses `Verify` for integrity before state changes
- passes `ParentExpectation` (`ExpectAbsentParent` / `ExpectParentCommit`) for optimistic concurrency

The store remains policy-free: it persists and verifies, it does not decide
workflow transitions.
