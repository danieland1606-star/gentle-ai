package reviewtransaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompactRiskSourceAutomaticAndExplicit(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")

	tests := []struct {
		name   string
		risk   RiskLevel
		source RiskSource
		lenses []string
	}{
		{name: "automatic", risk: RiskMedium, source: RiskSourceAutomatic, lenses: []string{LensReliability}},
		{name: "explicit high", risk: RiskHigh, source: RiskSourceExplicit, lenses: append([]string(nil), supportedLenses...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newCompactRiskSourceState(t, repo, "risk-source-"+strings.ReplaceAll(tt.name, " ", "-"), tt.risk, tt.source, tt.lenses)
			record, payload, err := makeCompactRecord(state)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parseCompactRecord(payload, state.LineageID)
			if err != nil || parsed.State.RiskSource != tt.source || parsed.Revision != record.Revision {
				t.Fatalf("parsed record = %#v, %v", parsed, err)
			}
			receipt := terminalRiskSourceReceipt(t, state)
			receiptPayload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			parsedReceipt, err := ParseCompactReceipt(receiptPayload)
			if err != nil || parsedReceipt.RiskSource != tt.source {
				t.Fatalf("parsed receipt = %#v, %v", parsedReceipt, err)
			}
		})
	}
}

func TestCompactExplicitRiskSourceRequiresHigh(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	for _, risk := range []RiskLevel{RiskLow, RiskMedium} {
		t.Run(string(risk), func(t *testing.T) {
			lines := 1
			_, err := NewCompactState(Start{LineageID: "explicit-" + string(risk), Mode: ModeOrdinaryBounded, Generation: 1,
				Snapshot: newCompactTestState(t, repo, "template-"+string(risk)).InitialSnapshot, PolicyHash: hash("policy"),
				RiskLevel: risk, RiskSource: RiskSourceExplicit, SelectedLenses: []string{}, OriginalChangedLines: &lines})
			if err == nil {
				t.Fatal("explicit non-high risk source accepted")
			}
		})
	}
}

func TestCompactHistoricalMissingRiskSourcePreservesRevision(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactRiskSourceState(t, repo, "historical-risk-source", RiskHigh, RiskSourceAutomatic, append([]string(nil), supportedLenses...))
	payload, revision := compactRecordWithoutRiskSource(t, state, false)

	parsed, err := parseCompactRecord(payload, state.LineageID)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.State.RiskSource != RiskSourceAutomatic || parsed.Revision != revision {
		t.Fatalf("historical record = %#v", parsed)
	}

	receipt := terminalRiskSourceReceipt(t, state)
	receiptPayload := compactJSONWithoutField(t, receipt, "risk_source")
	parsedReceipt, err := ParseCompactReceipt(receiptPayload)
	if err != nil || parsedReceipt.RiskSource != RiskSourceAutomatic {
		t.Fatalf("historical receipt = %#v, %v", parsedReceipt, err)
	}
}

func TestCompactRiskSourceRejectsPresentEmptyAndUnknown(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactRiskSourceState(t, repo, "invalid-risk-source", RiskHigh, RiskSourceAutomatic, append([]string(nil), supportedLenses...))
	receipt := terminalRiskSourceReceipt(t, state)

	for _, source := range []RiskSource{"", "unknown"} {
		t.Run(string(source), func(t *testing.T) {
			state.RiskSource = source
			_, payload, err := makeCompactRecord(state)
			if err == nil {
				_, err = parseCompactRecord(payload, state.LineageID)
			}
			if err == nil {
				t.Fatalf("state risk source %q accepted", source)
			}
			receipt.RiskSource = source
			receiptPayload, marshalErr := json.Marshal(receipt)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, err := ParseCompactReceipt(receiptPayload); err == nil {
				t.Fatalf("receipt risk source %q accepted", source)
			}
		})
	}
}

func TestCompactMissingRiskSourceCombinesWithRetiredFields(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactRiskSourceState(t, repo, "historical-combined", RiskMedium, RiskSourceAutomatic, []string{LensReliability})
	state.Recovery = &CompactRecoveryProvenance{PredecessorLineageID: "historical-predecessor", PredecessorRevision: hash("a"),
		Disposition: RecoveryInvalidated, Reason: "historical recovery", Actor: "maintainer", RecoveredAt: time.Unix(1, 0).UTC()}
	payload, revision := compactRecordWithoutRiskSource(t, state, true)

	parsed, err := parseCompactRecord(payload, state.LineageID)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.State.RiskSource != RiskSourceAutomatic || parsed.Revision != revision || !parsed.HistoricalCompat {
		t.Fatalf("combined historical record = %#v", parsed)
	}
	transport, err := ParseCompactTransport(compactHistoricalTransportPayload(t, json.RawMessage(payload), nil))
	if err != nil || transport.Record.Revision != revision || !transport.Record.HistoricalCompat {
		t.Fatalf("combined historical transport = %#v, %v", transport, err)
	}
}

func TestCompactHistoricalTransportMissingRiskSource(t *testing.T) {
	source := initSnapshotRepo(t)
	writeSnapshotFile(t, source, "tracked.txt", "candidate\n")
	gitSnapshot(t, source, "add", "tracked.txt")
	gitSnapshot(t, source, "commit", "-m", "candidate")
	state := newCompactRevisionState(t, source, "historical-transport")
	state.RiskSource = RiskSourceAutomatic
	results := make([]LensResult, len(state.SelectedLenses))
	for index, lens := range state.SelectedLenses {
		results[index] = LensResult{Lens: lens, Findings: []Finding{}, Evidence: []string{"review completed"}}
	}
	if err := state.CompleteReview(CompactReviewInput{LensResults: results}); err != nil {
		t.Fatal(err)
	}
	if err := state.CompleteVerification([]byte("tests pass\n"), true); err != nil {
		t.Fatal(err)
	}
	recordPayload, revision := compactRecordWithoutRiskSource(t, state, false)
	var record json.RawMessage
	if err := json.Unmarshal(recordPayload, &record); err != nil {
		t.Fatal(err)
	}
	receipt, err := state.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	receiptPayload := json.RawMessage(compactJSONWithoutField(t, receipt, "risk_source"))
	payload := compactHistoricalTransportPayload(t, record, receiptPayload)

	parsed, err := ParseCompactTransport(payload)
	if err != nil || parsed.Record.Revision != revision || parsed.Record.State.RiskSource != RiskSourceAutomatic || parsed.Receipt.RiskSource != RiskSourceAutomatic {
		t.Fatalf("historical transport = %#v, %v", parsed, err)
	}
	destination := filepath.Join(t.TempDir(), "clone")
	gitSnapshot(t, source, "clone", "--no-local", source, destination)
	if _, err := ImportCompactTransport(context.Background(), destination, parsed); err != nil {
		t.Fatal(err)
	}
	store, _ := CompactAuthoritativeStore(context.Background(), destination, state.LineageID)
	persisted, err := os.ReadFile(store.StatePath())
	var persistedCanonical, originalCanonical bytes.Buffer
	compactErr := json.Compact(&persistedCanonical, persisted)
	if compactErr == nil {
		compactErr = json.Compact(&originalCanonical, recordPayload)
	}
	if err != nil || compactErr != nil || !bytes.Equal(persistedCanonical.Bytes(), originalCanonical.Bytes()) {
		t.Fatalf("historical import changed canonical record: %v", err)
	}

	var transportFields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &transportFields); err != nil {
		t.Fatal(err)
	}
	transportFields["bundle_digest"] = json.RawMessage(`"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	tampered, _ := json.Marshal(transportFields)
	if _, err := ParseCompactTransport(tampered); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered historical transport error = %v", err)
	}
}

func compactHistoricalTransportPayload(t *testing.T, record, receipt json.RawMessage) []byte {
	t.Helper()
	transport := struct {
		Schema       string          `json:"schema"`
		Record       json.RawMessage `json:"record"`
		Receipt      json.RawMessage `json:"receipt,omitempty"`
		BundleDigest string          `json:"bundle_digest"`
	}{Schema: CompactTransportSchema, Record: record, Receipt: receipt}
	transport.BundleDigest = compactRawTransportDigest(transport.Schema, record, receipt)
	payload, err := json.Marshal(transport)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestCompactMalformedQuarantinePreflightAcceptsRiskSource(t *testing.T) {
	repo := initSnapshotRepo(t)
	lineage := "realistic-risk-source-v9"
	state := syntheticMalformedCompactState(t, repo, lineage)
	state.RiskLevel = RiskHigh
	state.RiskSource = RiskSourceExplicit
	state.SelectedLenses = append([]string(nil), supportedLenses...)
	payload := writeMalformedCompactRecord(t, repo, state)

	assessment, err := AssessCompactMalformedQuarantine(context.Background(), repo, lineage)
	if err != nil || !assessment.Eligible {
		t.Fatalf("assessment = %#v, %v", assessment, err)
	}
	base, _, err := reviewAuthorityRoot(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(base, "v2", lineage, compactStateFileName))
	if err != nil || !bytes.Equal(persisted, payload) {
		t.Fatalf("preflight changed authority: %v", err)
	}
}

func newCompactRiskSourceState(t *testing.T, repo, lineage string, risk RiskLevel, source RiskSource, lenses []string) CompactState {
	t.Helper()
	template := newCompactTestState(t, repo, lineage+"-template")
	lines := template.OriginalChangedLines
	state, err := NewCompactState(Start{LineageID: lineage, Mode: ModeOrdinaryBounded, Generation: 1,
		Snapshot: template.InitialSnapshot, PolicyHash: template.PolicyHash, RiskLevel: risk, RiskSource: source,
		SelectedLenses: lenses, OriginalChangedLines: &lines})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func terminalRiskSourceReceipt(t *testing.T, state CompactState) CompactReceipt {
	t.Helper()
	state.State = StateApproved
	state.EvidenceHash = hash("e")
	receipt, err := state.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func compactRecordWithoutRiskSource(t *testing.T, state CompactState, retired bool) ([]byte, string) {
	t.Helper()
	stateFields := compactJSONObject(t, state)
	delete(stateFields, "risk_source")
	if retired {
		stateFields["zero_edit_escalation"] = json.RawMessage(`true`)
		var recovery map[string]json.RawMessage
		if err := json.Unmarshal(stateFields["recovery"], &recovery); err != nil {
			t.Fatal(err)
		}
		recovery["review_start"] = json.RawMessage(`{"legacy":true}`)
		recoveryPayload, err := json.Marshal(recovery)
		if err != nil {
			t.Fatal(err)
		}
		stateFields["recovery"] = recoveryPayload
	}
	statePayload, err := json.Marshal(stateFields)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(CompactStateSchema+"\x00"), statePayload...))
	revision := "sha256:" + hex.EncodeToString(sum[:])
	record := struct {
		Schema   string          `json:"schema"`
		Revision string          `json:"revision"`
		State    json.RawMessage `json:"state"`
	}{Schema: compactRecordSchema, Revision: revision, State: statePayload}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(payload, '\n'), revision
}

func compactJSONWithoutField(t *testing.T, value any, field string) []byte {
	t.Helper()
	fields := compactJSONObject(t, value)
	delete(fields, field)
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func compactJSONObject(t *testing.T, value any) map[string]json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}
