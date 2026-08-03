// Package bootdoctor implements deterministic Boot Doctor analysis.
//
// Boot Doctor is a pure analyzer: given a verified Case snapshot context and a
// WindowsBootTopology, it emits typed Finding documents. It does not execute
// repairs, spawn processes, call the gateway, mutate the filesystem, or grant
// mutation authority. mutation_eligibility on topology is treated only as a
// diagnostic signal.
//
// Finding codes are recorded as the first limitations entry in the form
// "finding_code:<code>" so the existing finding 1.0.0 contract remains
// unchanged. Finding IDs are deterministic hashes independent of timestamps.
package bootdoctor
