// Package coordinator implements the local non-mutating Recovery Coordinator.
//
// The Coordinator is the only authority allowed to change Recovery Case
// workflow state. It commits immutable snapshots through the Case Store,
// enforces legal transitions for the PR #17 subset, and records typed audit
// events. It does not execute operations, call the gateway, or mutate a
// recovery target.
//
// Idempotency model (PR #17):
// Case Store Commit is idempotent for an identical canonical Snapshot
// (same snapshot_id as head). Full command_id payload idempotency is not
// claimed; optional command_id may be recorded on coordinator events for
// forward compatibility.
package coordinator
