package reviewtransaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const CompactMalformedQuarantineSchema = "gentle-ai.compact-malformed-quarantine/v1"
const CompactMalformedReasonHistoricalTerminalArtifacts = "historical_terminal_artifacts_incompatible_with_current_schema"
const compactMalformedAuthorizationSchema = "gentle-ai.compact-malformed-quarantine-authorization/v1"

type CompactMalformedQuarantineAssessment struct {
	Eligible          bool     `json:"eligible"`
	LineageID         string   `json:"lineage_id"`
	PhysicalStateSHA  string   `json:"physical_state_sha256,omitempty"`
	DeclaredRevision  string   `json:"declared_revision,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	RelatedEventPaths []string `json:"related_event_paths"`
	Refusal           string   `json:"refusal,omitempty"`
}
type CompactMalformedQuarantineRequest struct {
	Repository       string    `json:"repository"`
	LineageID        string    `json:"lineage_id"`
	ExpectedStateSHA string    `json:"expected_state_sha256"`
	ExpectedRevision string    `json:"expected_revision"`
	Actor            string    `json:"actor"`
	Reason           string    `json:"reason"`
	AnomalyClass     string    `json:"class"`
	Authorization    string    `json:"maintainer_authorization"`
	QuarantinedAt    time.Time `json:"quarantined_at,omitempty"`
}
type CompactMalformedQuarantineRecord struct {
	Schema            string    `json:"schema"`
	Status            string    `json:"status"`
	RecordIdentity    string    `json:"record_identity"`
	Repository        string    `json:"repository"`
	LineageID         string    `json:"lineage_id"`
	PhysicalStateSHA  string    `json:"physical_state_sha256"`
	DeclaredRevision  string    `json:"declared_revision"`
	ClassifiedReason  string    `json:"classified_reason"`
	MaintainerReason  string    `json:"maintainer_reason"`
	Actor             string    `json:"actor"`
	QuarantinedAt     time.Time `json:"quarantined_at"`
	RelatedEventPaths []string  `json:"related_event_paths"`
	QuarantinePath    string    `json:"quarantine_path"`
}

func PrepareCompactMalformedQuarantine(ctx context.Context, repo, lineage, actor, reason string) (CompactMalformedQuarantineAssessment, CompactMalformedQuarantineRequest, error) {
	assessment, err := AssessCompactMalformedQuarantine(ctx, repo, lineage)
	if err != nil || !assessment.Eligible {
		return assessment, CompactMalformedQuarantineRequest{}, err
	}
	_, root, err := reviewAuthorityRoot(ctx, repo)
	if err != nil {
		return assessment, CompactMalformedQuarantineRequest{}, err
	}
	identity, err := reviewRepositoryIdentityAtRoot(ctx, root)
	if err != nil {
		return assessment, CompactMalformedQuarantineRequest{}, err
	}
	request := CompactMalformedQuarantineRequest{Repository: identity.RepositoryIdentity, LineageID: lineage, ExpectedStateSHA: assessment.PhysicalStateSHA, ExpectedRevision: assessment.DeclaredRevision, Actor: strings.TrimSpace(actor), Reason: strings.TrimSpace(reason), AnomalyClass: assessment.Reason}
	request.Authorization = CompactMalformedQuarantineAuthorization(request)
	return assessment, request, nil
}

type compactMalformedEnvelope struct {
	Schema   string          `json:"schema"`
	Revision string          `json:"revision"`
	State    json.RawMessage `json:"state"`
}
type compactMalformedHeader struct {
	Schema             string          `json:"schema"`
	LineageID          string          `json:"lineage_id"`
	State              State           `json:"state"`
	Recovery           json.RawMessage `json:"recovery"`
	LensResults        json.RawMessage `json:"lens_results"`
	Findings           json.RawMessage `json:"findings"`
	Classifications    json.RawMessage `json:"classifications"`
	Outcomes           json.RawMessage `json:"outcomes"`
	FixFindingIDs      json.RawMessage `json:"fix_finding_ids"`
	InvalidationReason string          `json:"invalidation_reason"`
}

func CompactMalformedQuarantineAuthorization(r CompactMalformedQuarantineRequest) string {
	return strings.Join([]string{compactMalformedAuthorizationSchema, "repository=" + r.Repository, "lineage=" + r.LineageID, "physical_state_sha256=" + r.ExpectedStateSHA, "revision=" + r.ExpectedRevision, "actor=" + r.Actor, "reason=" + r.Reason, "class=" + r.AnomalyClass}, "\n") + "\n"
}

func AssessCompactMalformedQuarantine(ctx context.Context, repo, lineage string) (CompactMalformedQuarantineAssessment, error) {
	a := CompactMalformedQuarantineAssessment{LineageID: lineage, RelatedEventPaths: []string{}}
	if err := ctx.Err(); err != nil {
		return a, err
	}
	if validateLineageID(lineage) != nil || isReservedCompactNamespace(lineage) {
		a.Refusal = "invalid or reserved lineage"
		return a, nil
	}
	base, _, err := reviewAuthorityRoot(ctx, repo)
	if err != nil {
		return a, err
	}
	dir := filepath.Join(base, "v2", lineage)
	payload, err := os.ReadFile(filepath.Join(dir, compactStateFileName))
	if err != nil {
		a.Refusal = "state is unreadable"
		return a, nil
	}
	a.PhysicalStateSHA = malformedDigest(payload)
	if _, err = os.Lstat(filepath.Join(dir, compactReceiptFileName)); err == nil {
		a.Refusal = "receipt exists"
		return a, nil
	} else if !os.IsNotExist(err) {
		a.Refusal = "receipt status is ambiguous"
		return a, nil
	}
	var envelope compactMalformedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		a.Refusal = "physical JSON envelope is not parseable"
		return a, nil
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		a.Refusal = "physical JSON contains multiple values"
		return a, nil
	}
	a.DeclaredRevision = envelope.Revision
	var compacted bytes.Buffer
	if envelope.Schema != compactRecordSchema || !validSHA256(envelope.Revision) || json.Compact(&compacted, envelope.State) != nil {
		a.Refusal = "envelope identity is invalid"
		return a, nil
	}
	sum := sha256.Sum256(append([]byte(CompactStateSchema+"\x00"), compacted.Bytes()...))
	if envelope.Revision != "sha256:"+hex.EncodeToString(sum[:]) {
		a.Refusal = "declared state checksum mismatch"
		return a, nil
	}
	var header compactMalformedHeader
	if json.Unmarshal(envelope.State, &header) != nil || header.Schema != CompactStateSchema || header.LineageID != lineage {
		a.Refusal = "state identity is invalid"
		return a, nil
	}
	if header.State != StateInvalidated || strings.TrimSpace(header.InvalidationReason) == "" {
		a.Refusal = "state is not terminal invalidated"
		return a, nil
	}
	var strict CompactRecord
	strictDecoder := json.NewDecoder(bytes.NewReader(payload))
	strictDecoder.DisallowUnknownFields()
	if strictDecoder.Decode(&strict) != nil {
		a.Refusal = "state is structurally incompatible"
		return a, nil
	}
	if strict.State.Validate() == nil {
		a.Refusal = "state is semantically valid"
		return a, nil
	}
	if !malformedRawNonEmpty(header.LensResults, false) && !malformedRawNonEmpty(header.Findings, false) && !malformedRawNonEmpty(header.Classifications, true) && !malformedRawNonEmpty(header.Outcomes, true) && !malformedRawNonEmpty(header.FixFindingIDs, false) {
		a.Refusal = "historical artifacts are absent"
		return a, nil
	}
	normalized := strict.State
	normalized.LensResults = []LensResult{}
	normalized.Findings = []Finding{}
	normalized.Classifications = map[string]FindingEvidence{}
	normalized.Outcomes = map[string]EvidenceOutcome{}
	normalized.FixFindingIDs = []string{}
	if normalized.Validate() != nil {
		a.Refusal = "state has independent semantic corruption"
		return a, nil
	}
	if err = rejectMalformedSuccessors(base, lineage); err != nil {
		a.Refusal = err.Error()
		return a, nil
	}
	a.RelatedEventPaths, err = malformedRelatedEvents(base, lineage)
	if err != nil {
		a.Refusal = err.Error()
		return a, nil
	}
	a.Eligible = true
	a.Reason = CompactMalformedReasonHistoricalTerminalArtifacts
	return a, nil
}

func malformedRawNonEmpty(raw json.RawMessage, object bool) bool {
	if object {
		var v map[string]json.RawMessage
		return json.Unmarshal(raw, &v) == nil && len(v) > 0
	}
	var v []json.RawMessage
	return json.Unmarshal(raw, &v) == nil && len(v) > 0
}
func malformedDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func rejectMalformedSuccessors(base, lineage string) error {
	entries, err := os.ReadDir(filepath.Join(base, "v2"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !isCompactLineageEntry(entry) || entry.Name() == lineage {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(base, "v2", entry.Name(), compactStateFileName))
		if readErr != nil {
			return fmt.Errorf("ambiguous compact authority %s", entry.Name())
		}
		var envelope compactMalformedEnvelope
		var header compactMalformedHeader
		if json.Unmarshal(payload, &envelope) != nil || json.Unmarshal(envelope.State, &header) != nil {
			return fmt.Errorf("ambiguous compact authority %s", entry.Name())
		}
		if len(header.Recovery) > 0 && !bytes.Equal(header.Recovery, []byte("null")) {
			var recovery struct {
				PredecessorLineageID string `json:"predecessor_lineage_id"`
			}
			if json.Unmarshal(header.Recovery, &recovery) != nil {
				return fmt.Errorf("ambiguous compact recovery %s", entry.Name())
			}
			if recovery.PredecessorLineageID == lineage {
				return fmt.Errorf("lineage has live successor %s", entry.Name())
			}
		}
	}
	return nil
}
func malformedRelatedEvents(base, lineage string) ([]string, error) {
	var matches []string
	for _, namespace := range []string{"compatibility", "maintenance"} {
		root := filepath.Join(base, "v2", namespace)
		entries, err := os.ReadDir(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				return nil, fmt.Errorf("ambiguous %s event", namespace)
			}
			payload, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
			if readErr != nil {
				return nil, readErr
			}
			if bytes.Contains(payload, []byte(lineage)) {
				matches = append(matches, filepath.ToSlash(filepath.Join("v2", namespace, entry.Name())))
			}
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func QuarantineMalformedCompact(ctx context.Context, repo string, request CompactMalformedQuarantineRequest) (CompactMalformedQuarantineRecord, error) {
	if request.AnomalyClass != CompactMalformedReasonHistoricalTerminalArtifacts || strings.TrimSpace(request.Actor) == "" || strings.TrimSpace(request.Reason) == "" || !validSHA256(request.ExpectedStateSHA) || !validSHA256(request.ExpectedRevision) {
		return CompactMalformedQuarantineRecord{}, errors.New("compact quarantine request is incomplete")
	}
	base, root, err := reviewAuthorityRoot(ctx, repo)
	if err != nil {
		return CompactMalformedQuarantineRecord{}, err
	}
	repository, err := reviewRepositoryIdentityAtRoot(ctx, root)
	if err != nil {
		return CompactMalformedQuarantineRecord{}, err
	}
	if request.Repository != repository.RepositoryIdentity || request.Authorization != CompactMalformedQuarantineAuthorization(request) {
		return CompactMalformedQuarantineRecord{}, errors.New("compact quarantine requires exact maintainer authorization")
	}
	maintenance, err := acquireMaintenanceLock(ctx, compactMaintenanceLockPath(base), maintenanceExclusive)
	if err != nil {
		return CompactMalformedQuarantineRecord{}, err
	}
	defer maintenance.Release()
	assessment, err := AssessCompactMalformedQuarantine(ctx, repo, request.LineageID)
	if err != nil {
		return CompactMalformedQuarantineRecord{}, err
	}
	if !assessment.Eligible {
		inspection, inspectErr := InspectCompactRecoveryEdges(ctx, repo)
		if inspectErr != nil || !inspection.Complete || !inspection.Valid {
			return CompactMalformedQuarantineRecord{}, errors.New("compact quarantine replay requires a healthy remaining inventory")
		}
		return replayMalformedRecord(base, request, assessment.Refusal)
	}
	if assessment.PhysicalStateSHA != request.ExpectedStateSHA || assessment.DeclaredRevision != request.ExpectedRevision {
		return CompactMalformedQuarantineRecord{}, ErrConcurrentUpdate
	}
	if request.QuarantinedAt.IsZero() {
		request.QuarantinedAt = time.Now().UTC()
	}
	record := CompactMalformedQuarantineRecord{Schema: CompactMalformedQuarantineSchema, Status: CompactReclaimPrepared, Repository: repository.RepositoryIdentity, LineageID: request.LineageID, PhysicalStateSHA: assessment.PhysicalStateSHA, DeclaredRevision: assessment.DeclaredRevision, ClassifiedReason: assessment.Reason, MaintainerReason: strings.TrimSpace(request.Reason), Actor: strings.TrimSpace(request.Actor), QuarantinedAt: request.QuarantinedAt.UTC(), RelatedEventPaths: assessment.RelatedEventPaths}
	record.RecordIdentity = malformedRecordIdentity(record)
	quarantineRoot := filepath.Join(base, "quarantine")
	if err = ensureCanonicalReviewQuarantineRoot(base, quarantineRoot); err != nil {
		return record, err
	}
	if err = os.MkdirAll(quarantineRoot, 0o755); err != nil {
		return record, err
	}
	record.QuarantinePath = filepath.Join(quarantineRoot, strings.TrimPrefix(record.RecordIdentity, "sha256:"))
	if err = os.Mkdir(record.QuarantinePath, 0o755); err != nil {
		if os.IsExist(err) {
			return replayMalformedRecord(base, request, "")
		}
		return record, err
	}
	if err = persistMalformedRecord(record); err != nil {
		return record, err
	}
	source := filepath.Join(base, "v2", request.LineageID)
	residue := filepath.Join(record.QuarantinePath, "residue")
	if err = os.Rename(source, residue); err != nil {
		return record, err
	}
	payload, err := os.ReadFile(filepath.Join(residue, compactStateFileName))
	if err != nil || malformedDigest(payload) != record.PhysicalStateSHA {
		return record, errors.New("quarantine byte verification failed")
	}
	if _, err = os.Stat(source); !os.IsNotExist(err) {
		return record, errors.New("quarantine source residue remains")
	}
	inspection, err := InspectCompactRecoveryEdges(ctx, repo)
	if err != nil || !inspection.Complete || !inspection.Valid {
		return record, errors.New("quarantine left the remaining compact inventory unhealthy")
	}
	record.Status = CompactReclaimCommitted
	if err = persistMalformedRecord(record); err != nil {
		return record, err
	}
	return record, nil
}
func malformedRecordIdentity(record CompactMalformedQuarantineRecord) string {
	record.RecordIdentity, record.QuarantinePath, record.Status = "", "", ""
	payload, _ := json.Marshal(record)
	return malformedDigest(payload)
}
func persistMalformedRecord(record CompactMalformedQuarantineRecord) error {
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(record.QuarantinePath, "compact-quarantine-record.json"), append(payload, '\n'), 0o644)
}
func replayMalformedRecord(base string, request CompactMalformedQuarantineRequest, refusal string) (CompactMalformedQuarantineRecord, error) {
	entries, _ := os.ReadDir(filepath.Join(base, "quarantine"))
	var found *CompactMalformedQuarantineRecord
	for _, entry := range entries {
		payload, err := os.ReadFile(filepath.Join(base, "quarantine", entry.Name(), "compact-quarantine-record.json"))
		if err != nil {
			continue
		}
		var record CompactMalformedQuarantineRecord
		if json.Unmarshal(payload, &record) == nil && record.Schema == CompactMalformedQuarantineSchema && record.Repository == request.Repository && record.LineageID == request.LineageID && record.PhysicalStateSHA == request.ExpectedStateSHA && record.DeclaredRevision == request.ExpectedRevision && record.Actor == strings.TrimSpace(request.Actor) && record.MaintainerReason == strings.TrimSpace(request.Reason) && record.ClassifiedReason == request.AnomalyClass {
			if record.Status == CompactReclaimPrepared {
				state, readErr := os.ReadFile(filepath.Join(record.QuarantinePath, "residue", compactStateFileName))
				if readErr != nil || malformedDigest(state) != record.PhysicalStateSHA {
					return CompactMalformedQuarantineRecord{}, errors.New("prepared compact quarantine is incomplete or drifted")
				}
				record.Status = CompactReclaimCommitted
				if err := persistMalformedRecord(record); err != nil {
					return record, err
				}
			}
			if record.Status != CompactReclaimCommitted {
				continue
			}
			if found != nil {
				return CompactMalformedQuarantineRecord{}, errors.New("ambiguous committed quarantine replay")
			}
			copy := record
			found = &copy
		}
	}
	if found != nil {
		return *found, nil
	}
	return CompactMalformedQuarantineRecord{}, fmt.Errorf("compact quarantine refused: %s", refusal)
}
