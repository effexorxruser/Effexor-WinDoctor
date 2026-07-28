// Package legacyreport imports diagnostic-report 1.3.0 into recovery domain
// documents (CaseManifest, Target, EvidenceBundle).
//
// The importer is a pure deterministic transform: no filesystem writes, no
// command execution, no global mutable state, and no time.Now().
package legacyreport
