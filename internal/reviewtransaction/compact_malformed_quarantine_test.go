package reviewtransaction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompactMalformedQuarantineSyntheticV9(t *testing.T) {
	repo := initSnapshotRepo(t)
	lineage := "synthetic-command-fix-v9"
	payload := writeSyntheticMalformedCompact(t, repo, lineage)
	base, _, err := reviewAuthorityRoot(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"compatibility", "maintenance"} {
		dir := filepath.Join(base, "v2", namespace)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "event.json"), []byte(`{"lineage_id":"`+lineage+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	assessment, err := AssessCompactMalformedQuarantine(context.Background(), repo, lineage)
	if err != nil || !assessment.Eligible || len(assessment.RelatedEventPaths) != 2 {
		t.Fatalf("assessment=%#v err=%v", assessment, err)
	}
	repository, err := reviewRepositoryIdentityAtRoot(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	request := CompactMalformedQuarantineRequest{Repository: repository.RepositoryIdentity, LineageID: lineage, ExpectedStateSHA: shaBytes(payload), ExpectedRevision: assessment.DeclaredRevision, Actor: "maintainer@example.com", Reason: "retire synthetic historical authority", AnomalyClass: CompactMalformedReasonHistoricalTerminalArtifacts, QuarantinedAt: time.Unix(1, 0).UTC()}
	request.Authorization = CompactMalformedQuarantineAuthorization(request)
	record, err := QuarantineMalformedCompact(context.Background(), repo, request)
	if err != nil || record.Status != CompactReclaimCommitted {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	got, err := os.ReadFile(filepath.Join(record.QuarantinePath, "residue", compactStateFileName))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("bytes changed: %v", err)
	}
	record.Status = CompactReclaimPrepared
	if err := persistMalformedRecord(record); err != nil {
		t.Fatal(err)
	}
	replay, err := QuarantineMalformedCompact(context.Background(), repo, request)
	if err != nil || replay.RecordIdentity != record.RecordIdentity || replay.Status != CompactReclaimCommitted {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	stores, err := DiscoverCompactStores(context.Background(), repo)
	if err != nil || len(stores) != 0 {
		t.Fatalf("stores=%v err=%v", stores, err)
	}
}

func TestCompactMalformedQuarantineConcurrentReplayConverges(t *testing.T) {
	repo := initSnapshotRepo(t)
	lineage := "synthetic-race"
	payload := writeSyntheticMalformedCompact(t, repo, lineage)
	assessment, _ := AssessCompactMalformedQuarantine(context.Background(), repo, lineage)
	identity, _ := reviewRepositoryIdentityAtRoot(context.Background(), repo)
	request := CompactMalformedQuarantineRequest{Repository: identity.RepositoryIdentity, LineageID: lineage, ExpectedStateSHA: shaBytes(payload), ExpectedRevision: assessment.DeclaredRevision, Actor: "maintainer", Reason: "race replay", AnomalyClass: CompactMalformedReasonHistoricalTerminalArtifacts, QuarantinedAt: time.Unix(1, 0).UTC()}
	request.Authorization = CompactMalformedQuarantineAuthorization(request)
	var wg sync.WaitGroup
	identities := make(chan string, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, err := QuarantineMalformedCompact(context.Background(), repo, request)
			errs <- err
			identities <- record.RecordIdentity
		}()
	}
	wg.Wait()
	close(errs)
	close(identities)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var want string
	for identity := range identities {
		if want == "" {
			want = identity
		} else if identity != want {
			t.Fatalf("race identities differ: %q != %q", identity, want)
		}
	}
}

func TestCompactMalformedQuarantineRejectsUnsafeWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*CompactMalformedQuarantineRequest)
	}{
		{name: "authorization", mutate: func(r *CompactMalformedQuarantineRequest) { r.Authorization += "x" }},
		{name: "revision drift", mutate: func(r *CompactMalformedQuarantineRequest) { r.ExpectedRevision = hash("drift") }},
		{name: "physical drift", mutate: func(r *CompactMalformedQuarantineRequest) { r.ExpectedStateSHA = hash("drift") }},
		{name: "class", mutate: func(r *CompactMalformedQuarantineRequest) { r.AnomalyClass = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := initSnapshotRepo(t)
			lineage := "synthetic-v9"
			payload := writeSyntheticMalformedCompact(t, repo, lineage)
			assessment, _ := AssessCompactMalformedQuarantine(context.Background(), repo, lineage)
			repository, _ := reviewRepositoryIdentityAtRoot(context.Background(), repo)
			r := CompactMalformedQuarantineRequest{Repository: repository.RepositoryIdentity, LineageID: lineage, ExpectedStateSHA: shaBytes(payload), ExpectedRevision: assessment.DeclaredRevision, Actor: "maintainer", Reason: "reason", AnomalyClass: CompactMalformedReasonHistoricalTerminalArtifacts, QuarantinedAt: time.Unix(1, 0).UTC()}
			r.Authorization = CompactMalformedQuarantineAuthorization(r)
			tc.mutate(&r)
			_, err := QuarantineMalformedCompact(context.Background(), repo, r)
			if err == nil {
				t.Fatal("unsafe request accepted")
			}
			base, _, _ := reviewAuthorityRoot(context.Background(), repo)
			got, readErr := os.ReadFile(filepath.Join(base, "v2", lineage, compactStateFileName))
			if readErr != nil || string(got) != string(payload) {
				t.Fatalf("request mutated authority: %v", readErr)
			}
		})
	}
}

func TestCompactMalformedQuarantineRejectsReceiptAndSuccessor(t *testing.T) {
	for _, successor := range []bool{false, true} {
		repo := initSnapshotRepo(t)
		lineage := "synthetic-v9"
		writeSyntheticMalformedCompact(t, repo, lineage)
		base, _, _ := reviewAuthorityRoot(context.Background(), repo)
		if successor {
			next := newCompactTestState(t, repo, "synthetic-successor")
			next.Recovery = &CompactRecoveryProvenance{PredecessorLineageID: lineage, PredecessorRevision: hash("p"), Disposition: RecoveryInvalidated, Reason: "r", Actor: "a", RecoveredAt: time.Unix(1, 0).UTC()}
			writeMalformedCompactRecord(t, repo, next)
		} else if err := os.WriteFile(filepath.Join(base, "v2", lineage, compactReceiptFileName), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := AssessCompactMalformedQuarantine(context.Background(), repo, lineage)
		if err != nil || a.Eligible {
			t.Fatalf("unsafe target eligible: %#v err=%v", a, err)
		}
	}
}

func TestCompactMalformedQuarantineRequiresArtifactsAsSoleSemanticDefect(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*CompactState)
		eligible bool
	}{
		{name: "historical artifacts only", mutate: func(*CompactState) {}, eligible: true},
		{name: "historical artifacts plus invalid policy hash", mutate: func(state *CompactState) {
			state.PolicyHash = "sha256:" + strings.Repeat("A", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := initSnapshotRepo(t)
			lineage := "synthetic-sole-cause"
			state := syntheticMalformedCompactState(t, repo, lineage)
			tc.mutate(&state)
			payload := writeMalformedCompactRecord(t, repo, state)

			assessment, err := AssessCompactMalformedQuarantine(context.Background(), repo, lineage)
			if err != nil || assessment.Eligible != tc.eligible {
				t.Fatalf("assessment=%#v err=%v, eligible want %v", assessment, err, tc.eligible)
			}
			base, _, _ := reviewAuthorityRoot(context.Background(), repo)
			got, readErr := os.ReadFile(filepath.Join(base, "v2", lineage, compactStateFileName))
			if readErr != nil || string(got) != string(payload) {
				t.Fatalf("assessment mutated authority: %v", readErr)
			}
		})
	}
}

func writeSyntheticMalformedCompact(t *testing.T, repo, lineage string) []byte {
	t.Helper()
	return writeMalformedCompactRecord(t, repo, syntheticMalformedCompactState(t, repo, lineage))
}

func syntheticMalformedCompactState(t *testing.T, repo, lineage string) CompactState {
	t.Helper()
	state := newCompactTestState(t, repo, lineage)
	state.State = StateInvalidated
	state.InvalidationReason = "historical invalidation"
	state.Findings = []Finding{{ID: "SYN-001", Lens: "risk", Location: "synthetic.go:1", Severity: "HIGH", Claim: "synthetic historical finding", ProofRefs: []string{"synthetic-proof"}}}
	return state
}

func writeMalformedCompactRecord(t *testing.T, repo string, state CompactState) []byte {
	t.Helper()
	statePayload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte(CompactStateSchema+"\x00"), statePayload...))
	record := CompactRecord{Schema: compactRecordSchema, Revision: "sha256:" + hex.EncodeToString(sum[:]), State: state}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	base, _, err := reviewAuthorityRoot(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "v2", state.LineageID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, compactStateFileName), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	return payload
}

func shaBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestCompactMalformedAuthorizationIsLineBound(t *testing.T) {
	r := CompactMalformedQuarantineRequest{Repository: "sha256:" + strings.Repeat("a", 64), LineageID: "lineage", ExpectedStateSHA: "sha256:" + strings.Repeat("b", 64), ExpectedRevision: "sha256:" + strings.Repeat("c", 64), Actor: "actor", Reason: "reason", AnomalyClass: CompactMalformedReasonHistoricalTerminalArtifacts}
	a := CompactMalformedQuarantineAuthorization(r)
	for _, value := range []string{r.Repository, r.LineageID, r.ExpectedStateSHA, r.ExpectedRevision, r.Actor, r.Reason, r.AnomalyClass} {
		if !strings.Contains(a, value) {
			t.Fatalf("authorization missing %q", value)
		}
	}
}
