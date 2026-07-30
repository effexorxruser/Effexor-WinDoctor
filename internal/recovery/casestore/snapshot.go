package casestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

// Normalize empties optional collections so nil and empty slices serialize
// identically when preparing documents (no documents written for empty sets).
func (s *Snapshot) Normalize() {
	if s.Findings == nil {
		s.Findings = []domain.Finding{}
	}
	if s.RepairPlans == nil {
		s.RepairPlans = []domain.RepairPlan{}
	}
	if s.ExecutionEvents == nil {
		s.ExecutionEvents = []domain.ExecutionEvent{}
	}
	if s.VerificationReports == nil {
		s.VerificationReports = []domain.VerificationReport{}
	}
	if s.CoordinatorEvents == nil {
		s.CoordinatorEvents = []domain.CoordinatorEvent{}
	}
}

// Validate checks Snapshot domain invariants before commit.
func (s Snapshot) Validate() error {
	if err := s.Case.Validate(); err != nil {
		return fmt.Errorf("case: %w", err)
	}
	if len(s.Targets) == 0 {
		return fmt.Errorf("%w: targets must not be empty", ErrInvalidArgument)
	}
	if len(s.EvidenceBundles) == 0 {
		return fmt.Errorf("%w: evidence_bundles must not be empty", ErrInvalidArgument)
	}

	created, err := time.Parse(time.RFC3339, s.Case.CreatedAt)
	if err != nil {
		return fmt.Errorf("case.created_at: %w", err)
	}
	updated, err := time.Parse(time.RFC3339, s.Case.UpdatedAt)
	if err != nil {
		return fmt.Errorf("case.updated_at: %w", err)
	}
	if updated.Before(created) {
		return fmt.Errorf("%w: updated_at must not be before created_at", ErrInvalidArgument)
	}

	targetIDs := make(map[string]struct{}, len(s.Targets))
	for i, t := range s.Targets {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		if _, ok := targetIDs[t.TargetID]; ok {
			return fmt.Errorf("%w: duplicate target_id %q", ErrInvalidArgument, t.TargetID)
		}
		targetIDs[t.TargetID] = struct{}{}
	}

	caseTargetSet := make(map[string]struct{}, len(s.Case.TargetIDs))
	for _, id := range s.Case.TargetIDs {
		caseTargetSet[id] = struct{}{}
	}
	if len(caseTargetSet) != len(targetIDs) {
		return fmt.Errorf("%w: case.target_ids does not match targets set", ErrInvalidArgument)
	}
	for id := range targetIDs {
		if _, ok := caseTargetSet[id]; !ok {
			return fmt.Errorf("%w: target %q missing from case.target_ids", ErrInvalidArgument, id)
		}
	}
	for id := range caseTargetSet {
		if _, ok := targetIDs[id]; !ok {
			return fmt.Errorf("%w: case.target_ids entry %q has no target document", ErrInvalidArgument, id)
		}
	}

	evidenceIDs := make(map[string]struct{}, len(s.EvidenceBundles))
	artifactByID := make(map[string]domain.ArtifactRef)
	for i, e := range s.EvidenceBundles {
		if e.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: evidence_bundles[%d].case_id mismatch", ErrInvalidArgument, i)
		}
		if _, ok := evidenceIDs[e.EvidenceID]; ok {
			return fmt.Errorf("%w: duplicate evidence_id %q", ErrInvalidArgument, e.EvidenceID)
		}
		evidenceIDs[e.EvidenceID] = struct{}{}
		for j, a := range e.Artifacts {
			if err := rejectTraversal(a.RelativePath); err != nil {
				return fmt.Errorf("evidence_bundles[%d].artifacts[%d]: %w", i, j, err)
			}
			if prev, ok := artifactByID[a.ArtifactID]; ok {
				if !artifactRefsEqual(prev, a) {
					return fmt.Errorf("%w: divergent metadata for artifact_id %q", ErrInvalidArgument, a.ArtifactID)
				}
			} else {
				artifactByID[a.ArtifactID] = a
			}
		}
	}

	findingIDs := make(map[string]struct{}, len(s.Findings))
	for _, f := range s.Findings {
		if _, ok := findingIDs[f.FindingID]; ok {
			return fmt.Errorf("%w: duplicate finding_id %q", ErrInvalidArgument, f.FindingID)
		}
		findingIDs[f.FindingID] = struct{}{}
	}

	planIDs := make(map[string]struct{}, len(s.RepairPlans))
	for _, p := range s.RepairPlans {
		if _, ok := planIDs[p.PlanID]; ok {
			return fmt.Errorf("%w: duplicate plan_id %q", ErrInvalidArgument, p.PlanID)
		}
		planIDs[p.PlanID] = struct{}{}
	}

	executionIDs := make(map[string]struct{}, len(s.ExecutionEvents))
	for _, e := range s.ExecutionEvents {
		if _, ok := executionIDs[e.ExecutionID]; ok {
			return fmt.Errorf("%w: duplicate execution_id %q", ErrInvalidArgument, e.ExecutionID)
		}
		executionIDs[e.ExecutionID] = struct{}{}
	}

	verificationIDs := make(map[string]struct{}, len(s.VerificationReports))
	for _, v := range s.VerificationReports {
		if _, ok := verificationIDs[v.VerificationID]; ok {
			return fmt.Errorf("%w: duplicate verification_id %q", ErrInvalidArgument, v.VerificationID)
		}
		verificationIDs[v.VerificationID] = struct{}{}
	}

	eventIDs := make(map[string]struct{}, len(s.CoordinatorEvents))
	for _, ev := range s.CoordinatorEvents {
		if _, ok := eventIDs[ev.EventID]; ok {
			return fmt.Errorf("%w: duplicate coordinator event_id %q", ErrInvalidArgument, ev.EventID)
		}
		eventIDs[ev.EventID] = struct{}{}
	}

	docIDs := make(map[string]struct{})
	docIDs[s.Case.CaseID] = struct{}{}
	for id := range targetIDs {
		docIDs[id] = struct{}{}
	}
	for id := range evidenceIDs {
		docIDs[id] = struct{}{}
	}
	for id := range findingIDs {
		docIDs[id] = struct{}{}
	}
	for id := range planIDs {
		docIDs[id] = struct{}{}
	}
	for id := range executionIDs {
		docIDs[id] = struct{}{}
	}
	for id := range verificationIDs {
		docIDs[id] = struct{}{}
	}
	for id := range eventIDs {
		docIDs[id] = struct{}{}
	}
	if s.WorkflowState != nil {
		docIDs[domain.DocumentIDCaseWorkflowState] = struct{}{}
	}

	refs := domain.CrossRefs{
		CaseIDs:             setOf(s.Case.CaseID),
		TargetIDs:           targetIDs,
		EvidenceIDs:         evidenceIDs,
		FindingIDs:          findingIDs,
		PlanIDs:             planIDs,
		ExecutionIDs:        executionIDs,
		VerificationIDs:     verificationIDs,
		ArtifactIDs:         artifactIDSet(artifactByID),
		CoordinatorEventIDs: eventIDs,
		DocumentIDs:         docIDs,
	}

	for i, e := range s.EvidenceBundles {
		if err := e.ValidateEvidenceRefs(refs); err != nil {
			return fmt.Errorf("evidence_bundles[%d]: %w", i, err)
		}
	}
	for i, f := range s.Findings {
		if err := f.ValidateFindingRefs(refs); err != nil {
			return fmt.Errorf("findings[%d]: %w", i, err)
		}
		if f.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: findings[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, p := range s.RepairPlans {
		if err := p.ValidatePlanRefs(refs); err != nil {
			return fmt.Errorf("repair_plans[%d]: %w", i, err)
		}
		if p.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: repair_plans[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, e := range s.ExecutionEvents {
		if err := e.ValidateExecutionRefs(refs); err != nil {
			return fmt.Errorf("execution_events[%d]: %w", i, err)
		}
		if e.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: execution_events[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, v := range s.VerificationReports {
		if err := v.ValidateVerificationRefs(refs); err != nil {
			return fmt.Errorf("verification_reports[%d]: %w", i, err)
		}
		if v.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: verification_reports[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	for i, ev := range s.CoordinatorEvents {
		if err := ev.ValidateCoordinatorEventRefs(refs); err != nil {
			return fmt.Errorf("coordinator_events[%d]: %w", i, err)
		}
		if ev.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: coordinator_events[%d].case_id mismatch", ErrInvalidArgument, i)
		}
	}
	if s.WorkflowState != nil {
		if err := s.WorkflowState.ValidateWorkflowRefs(refs); err != nil {
			return fmt.Errorf("workflow_state: %w", err)
		}
		if s.WorkflowState.CaseID != s.Case.CaseID {
			return fmt.Errorf("%w: workflow_state.case_id mismatch", ErrInvalidArgument)
		}
		if !domain.CompatibleWorkflowAndCaseState(s.WorkflowState.State, s.Case.CurrentState) {
			return fmt.Errorf("%w: workflow state %q incompatible with case current_state %q",
				ErrInvalidArgument, s.WorkflowState.State, s.Case.CurrentState)
		}
		if err := validateWorkflowTransitionIntegrity(s); err != nil {
			return err
		}
	}
	return nil
}

// validateWorkflowTransitionIntegrity enforces the PR #17 revision model:
// WorkflowState.Revision equals the count of state-changing coordinator events,
// and last_transition_id identifies the last such event (by occurred_at, then event_id).
func validateWorkflowTransitionIntegrity(s Snapshot) error {
	ws := s.WorkflowState
	byID := make(map[string]domain.CoordinatorEvent, len(s.CoordinatorEvents))
	var changing []domain.CoordinatorEvent
	for _, ev := range s.CoordinatorEvents {
		byID[ev.EventID] = ev
		if _, ok := domain.StateChangingEventTypes[ev.EventType]; ok {
			changing = append(changing, ev)
		}
	}
	if uint64(len(changing)) != ws.Revision {
		return fmt.Errorf("%w: workflow revision %d != state-changing event count %d",
			ErrInvalidArgument, ws.Revision, len(changing))
	}
	last, ok := byID[ws.LastTransitionID]
	if !ok {
		return fmt.Errorf("%w: last_transition_id %q missing", ErrInvalidArgument, ws.LastTransitionID)
	}
	if last.CaseID != s.Case.CaseID {
		return fmt.Errorf("%w: last transition event case_id mismatch", ErrInvalidArgument)
	}
	if last.NextState != string(ws.State) {
		return fmt.Errorf("%w: last transition next_state %q != workflow state %q",
			ErrInvalidArgument, last.NextState, ws.State)
	}
	if _, ok := domain.StateChangingEventTypes[last.EventType]; !ok {
		return fmt.Errorf("%w: last_transition_id event type %q is not state-changing",
			ErrInvalidArgument, last.EventType)
	}
	if err := validateEventTransitionPair(last); err != nil {
		return err
	}
	if len(changing) == 0 {
		return fmt.Errorf("%w: workflow present without state-changing events", ErrInvalidArgument)
	}
	sort.Slice(changing, func(i, j int) bool {
		if changing[i].OccurredAt != changing[j].OccurredAt {
			return changing[i].OccurredAt < changing[j].OccurredAt
		}
		return changing[i].EventID < changing[j].EventID
	})
	tail := changing[len(changing)-1]
	if tail.EventID != ws.LastTransitionID {
		return fmt.Errorf("%w: last_transition_id %q is not the latest state-changing event %q",
			ErrInvalidArgument, ws.LastTransitionID, tail.EventID)
	}
	return nil
}

func validateEventTransitionPair(ev domain.CoordinatorEvent) error {
	if ev.EventType == domain.EventLegacyCaseAdopted {
		if ev.PreviousState == "" && ev.NextState == string(domain.WorkflowEvidenceCollected) {
			return nil
		}
		return fmt.Errorf("%w: legacy_case_adopted requires previous_state absent and next_state evidence_collected",
			ErrInvalidArgument)
	}
	wantType, ok := eventTypeForTransition(domain.WorkflowStateName(ev.PreviousState), domain.WorkflowStateName(ev.NextState))
	if !ok {
		return fmt.Errorf("%w: event %s has invalid transition %q -> %q",
			ErrInvalidArgument, ev.EventType, ev.PreviousState, ev.NextState)
	}
	if wantType != ev.EventType {
		return fmt.Errorf("%w: event type %q does not match transition %q -> %q (want %q)",
			ErrInvalidArgument, ev.EventType, ev.PreviousState, ev.NextState, wantType)
	}
	return nil
}

func eventTypeForTransition(from, to domain.WorkflowStateName) (domain.CoordinatorEventType, bool) {
	switch {
	case from == domain.WorkflowCreated && to == domain.WorkflowEvidenceCollected:
		return domain.EventCaseCreated, true
	case from == domain.WorkflowEvidenceCollected && to == domain.WorkflowAnalyzed:
		return domain.EventAnalysisCommitted, true
	case from == domain.WorkflowAnalyzed && to == domain.WorkflowAnalyzed:
		return domain.EventAnalysisCommitted, true
	case from == domain.WorkflowAnalyzed && to == domain.WorkflowPlanProposed:
		return domain.EventPlanCommitted, true
	case to == domain.WorkflowFailed && (from == domain.WorkflowCreated || from == domain.WorkflowEvidenceCollected || from == domain.WorkflowAnalyzed || from == domain.WorkflowPlanProposed):
		return domain.EventCaseFailed, true
	case to == domain.WorkflowCancelled && (from == domain.WorkflowCreated || from == domain.WorkflowEvidenceCollected || from == domain.WorkflowAnalyzed || from == domain.WorkflowPlanProposed):
		return domain.EventCaseCancelled, true
	default:
		return "", false
	}
}

func setOf(ids ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func artifactIDSet(m map[string]domain.ArtifactRef) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for id := range m {
		out[id] = struct{}{}
	}
	return out
}

func artifactRefsEqual(a, b domain.ArtifactRef) bool {
	return a.ArtifactID == b.ArtifactID &&
		a.Kind == b.Kind &&
		a.RelativePath == b.RelativePath &&
		strings.EqualFold(a.SHA256, b.SHA256) &&
		a.SizeBytes == b.SizeBytes &&
		a.CreatedAt == b.CreatedAt &&
		a.MediaClassification == b.MediaClassification
}

// SnapshotFromImporterResult converts a legacy importer Result into a Snapshot.
func SnapshotFromImporterResult(result legacyreport.Result) Snapshot {
	return Snapshot{
		Case:                result.Case,
		Targets:             append([]domain.Target(nil), result.Targets...),
		EvidenceBundles:     append([]domain.EvidenceBundle(nil), result.EvidenceBundles...),
		Findings:            []domain.Finding{},
		RepairPlans:         []domain.RepairPlan{},
		ExecutionEvents:     []domain.ExecutionEvent{},
		VerificationReports: []domain.VerificationReport{},
		CoordinatorEvents:   []domain.CoordinatorEvent{},
	}
}

type preparedDocument struct {
	RelativePath string
	MediaType    string
	Bytes        []byte
	SHA256       string
	SizeBytes    int64
}

func prepareDocuments(snap Snapshot) ([]preparedDocument, error) {
	snap.Normalize()
	var docs []preparedDocument

	caseBytes, err := marshalCanonical(snap.Case)
	if err != nil {
		return nil, fmt.Errorf("marshal case-manifest: %w", err)
	}
	docs = append(docs, documentEntry("case-manifest.json", caseBytes))

	if snap.WorkflowState != nil {
		raw, err := marshalCanonical(snap.WorkflowState)
		if err != nil {
			return nil, fmt.Errorf("marshal case-workflow-state: %w", err)
		}
		docs = append(docs, documentEntry("case-workflow-state.json", raw))
	}

	targets := append([]domain.Target(nil), snap.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })
	for _, t := range targets {
		if err := validateTargetID(t.TargetID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(t)
		if err != nil {
			return nil, fmt.Errorf("marshal target %s: %w", t.TargetID, err)
		}
		docs = append(docs, documentEntry("targets/"+t.TargetID+".json", raw))
	}

	bundles := append([]domain.EvidenceBundle(nil), snap.EvidenceBundles...)
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].EvidenceID < bundles[j].EvidenceID })
	for _, e := range bundles {
		if err := validateEvidenceID(e.EvidenceID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(e)
		if err != nil {
			return nil, fmt.Errorf("marshal evidence %s: %w", e.EvidenceID, err)
		}
		docs = append(docs, documentEntry("evidence/"+e.EvidenceID+".json", raw))
	}

	findings := append([]domain.Finding(nil), snap.Findings...)
	sort.Slice(findings, func(i, j int) bool { return findings[i].FindingID < findings[j].FindingID })
	for _, f := range findings {
		if err := validateFindingID(f.FindingID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(f)
		if err != nil {
			return nil, fmt.Errorf("marshal finding %s: %w", f.FindingID, err)
		}
		docs = append(docs, documentEntry("findings/"+f.FindingID+".json", raw))
	}

	plans := append([]domain.RepairPlan(nil), snap.RepairPlans...)
	sort.Slice(plans, func(i, j int) bool { return plans[i].PlanID < plans[j].PlanID })
	for _, p := range plans {
		if err := validatePlanID(p.PlanID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(p)
		if err != nil {
			return nil, fmt.Errorf("marshal plan %s: %w", p.PlanID, err)
		}
		docs = append(docs, documentEntry("plans/"+p.PlanID+".json", raw))
	}

	execs := append([]domain.ExecutionEvent(nil), snap.ExecutionEvents...)
	sort.Slice(execs, func(i, j int) bool { return execs[i].ExecutionID < execs[j].ExecutionID })
	for _, e := range execs {
		if err := validateExecutionID(e.ExecutionID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(e)
		if err != nil {
			return nil, fmt.Errorf("marshal execution %s: %w", e.ExecutionID, err)
		}
		docs = append(docs, documentEntry("executions/"+e.ExecutionID+".json", raw))
	}

	verifs := append([]domain.VerificationReport(nil), snap.VerificationReports...)
	sort.Slice(verifs, func(i, j int) bool { return verifs[i].VerificationID < verifs[j].VerificationID })
	for _, v := range verifs {
		if err := validateVerificationID(v.VerificationID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(v)
		if err != nil {
			return nil, fmt.Errorf("marshal verification %s: %w", v.VerificationID, err)
		}
		docs = append(docs, documentEntry("verifications/"+v.VerificationID+".json", raw))
	}

	events := append([]domain.CoordinatorEvent(nil), snap.CoordinatorEvents...)
	sort.Slice(events, func(i, j int) bool { return events[i].EventID < events[j].EventID })
	for _, ev := range events {
		if err := validateCoordinatorEventID(ev.EventID); err != nil {
			return nil, err
		}
		raw, err := marshalCanonical(ev)
		if err != nil {
			return nil, fmt.Errorf("marshal coordinator-event %s: %w", ev.EventID, err)
		}
		docs = append(docs, documentEntry("coordinator-events/"+ev.EventID+".json", raw))
	}

	sort.Slice(docs, func(i, j int) bool { return docs[i].RelativePath < docs[j].RelativePath })
	return docs, nil
}

func documentEntry(rel string, raw []byte) preparedDocument {
	sum := sha256.Sum256(raw)
	return preparedDocument{
		RelativePath: rel,
		MediaType:    mediaTypeJSON,
		Bytes:        raw,
		SHA256:       hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(raw)),
	}
}

func marshalCanonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

func collectArtifactRefs(snap Snapshot) ([]domain.ArtifactRef, error) {
	byID := make(map[string]domain.ArtifactRef)
	var order []string
	for _, e := range snap.EvidenceBundles {
		for _, a := range e.Artifacts {
			if err := validateArtifactID(a.ArtifactID); err != nil {
				return nil, err
			}
			if err := validateSHA256Hex(strings.ToLower(a.SHA256)); err != nil {
				return nil, err
			}
			a.SHA256 = strings.ToLower(a.SHA256)
			if prev, ok := byID[a.ArtifactID]; ok {
				if !artifactRefsEqual(prev, a) {
					return nil, fmt.Errorf("%w: divergent metadata for artifact_id %q", ErrInvalidArgument, a.ArtifactID)
				}
				continue
			}
			byID[a.ArtifactID] = a
			order = append(order, a.ArtifactID)
		}
	}
	sort.Strings(order)
	out := make([]domain.ArtifactRef, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

func buildSnapshotManifest(caseID string, createdAt string, docs []preparedDocument, arts []snapshotArtifactEntry) (snapshotManifest, []byte, error) {
	docEntries := make([]snapshotDocumentEntry, 0, len(docs))
	for _, d := range docs {
		docEntries = append(docEntries, snapshotDocumentEntry{
			RelativePath: d.RelativePath,
			SHA256:       d.SHA256,
			SizeBytes:    d.SizeBytes,
			MediaType:    d.MediaType,
		})
	}
	sort.Slice(docEntries, func(i, j int) bool { return docEntries[i].RelativePath < docEntries[j].RelativePath })
	if docEntries == nil {
		docEntries = []snapshotDocumentEntry{}
	}
	artsCopy := append([]snapshotArtifactEntry(nil), arts...)
	if artsCopy == nil {
		artsCopy = []snapshotArtifactEntry{}
	}
	sort.Slice(artsCopy, func(i, j int) bool { return artsCopy[i].ArtifactID < artsCopy[j].ArtifactID })

	body := struct {
		SchemaName    string                  `json:"schema_name"`
		SchemaVersion string                  `json:"schema_version"`
		CaseID        string                  `json:"case_id"`
		CreatedAt     string                  `json:"created_at"`
		Documents     []snapshotDocumentEntry `json:"documents"`
		Artifacts     []snapshotArtifactEntry `json:"artifacts"`
	}{
		SchemaName:    schemaSnapshotManifest,
		SchemaVersion: schemaVersion,
		CaseID:        caseID,
		CreatedAt:     createdAt,
		Documents:     docEntries,
		Artifacts:     artsCopy,
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		return snapshotManifest{}, nil, err
	}
	sum := sha256.Sum256(canonical)
	contentSHA := hex.EncodeToString(sum[:])
	snapshotID := "snapshot-" + contentSHA[:24]

	manifest := snapshotManifest{
		SchemaName:    schemaSnapshotManifest,
		SchemaVersion: schemaVersion,
		CaseID:        caseID,
		SnapshotID:    snapshotID,
		ContentSHA256: contentSHA,
		CreatedAt:     createdAt,
		Documents:     docEntries,
		Artifacts:     artsCopy,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return snapshotManifest{}, nil, err
	}
	return manifest, raw, nil
}

func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON content")
		}
		return err
	}
	return nil
}
