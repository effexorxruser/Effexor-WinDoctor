// Package coordinator implements the local non-mutating Recovery Coordinator.
//
// The Coordinator is the only authority allowed to change Recovery Case
// workflow state. It commits immutable snapshots through the Case Store,
// enforces legal transitions for the PR #17 subset, and records typed audit
// events. PR #18 adds read-only acquisition APIs (ExecuteReadOperation,
// ResolveWindowsBootTopology) that append Evidence and provenance records
// without mutating a recovery target or advancing workflow beyond
// evidence_collected. It does not call the gateway, approve repairs, or
// execute mutating operations.
//
// Idempotency model (PR #17):
// Case Store Commit is idempotent for an identical canonical Snapshot
// (same snapshot_id as head). Full command_id payload idempotency is not
// claimed; optional command_id may be recorded on coordinator events for
// forward compatibility. PR #18 acquisition requests are idempotent on
// identical request_id + canonical request payload.
package coordinator
