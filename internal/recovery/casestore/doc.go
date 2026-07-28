// Package casestore implements a local crash-consistent Case Store for the
// Effexor Recovery Platform.
//
// The store persists CaseManifest, Targets, and EvidenceBundles as immutable
// snapshots, content-addressed artifact blobs, and an append-only commit
// chain. The highest valid commit record is the current case state; there is
// no mutable CURRENT pointer. The rename that publishes the final commit
// record is the sole commit point.
//
// Artifact bytes are obtained only through ArtifactProvider. Store never opens
// ArtifactRef.relative_path as a filesystem path.
//
// Recommended roots (caller-supplied; this package never hard-codes a drive):
//
//	WinPE working storage:       X:\EffexorRecovery\work
//	Persistent technician store: <selected-drive>\EffexorRecovery
//
// Commit chain validation is tamper-evident for accidental damage and
// incomplete writes, but without signatures it is not tamper-proof against an
// attacker who can rewrite the entire history on disk.
//
// Directory durability (fsync of parent directories) is best-effort and varies
// by platform and filesystem. FAT/exFAT, removable media, and controllers with
// write cache may lose recently published metadata after power loss even when
// file contents were synced. CommitInfo.DurabilityWarnings and integrity
// reports surface these limitations; they are never silent successes.
package casestore
