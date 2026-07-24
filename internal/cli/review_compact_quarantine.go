package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gentleman-programming/gentle-ai/internal/reviewtransaction"
)

type ReviewCompactQuarantineResult struct {
	Operation  string                                                  `json:"operation"`
	Assessment *reviewtransaction.CompactMalformedQuarantineAssessment `json:"assessment,omitempty"`
	Request    *reviewtransaction.CompactMalformedQuarantineRequest    `json:"request,omitempty"`
	Record     *reviewtransaction.CompactMalformedQuarantineRecord     `json:"record,omitempty"`
}

func RunReviewCompactQuarantine(args []string, stdout io.Writer) error {
	flags := newReviewFlagSet("review quarantine-compact", stdout, "Preflight or atomically quarantine one narrowly classified terminal invalidated compact-v2 lineage without making it delivery-eligible.")
	cwd := flags.String("cwd", ".", "repository path")
	lineage := flags.String("lineage", "", "exact compact-v2 lineage")
	preflight := flags.Bool("preflight", false, "read-only classification and authorization template")
	repository := flags.String("repository", "", "repository identity from preflight")
	expectedSHA := flags.String("expected-state-sha256", "", "physical state SHA-256 from preflight")
	revision := flags.String("expected-revision", "", "declared revision from preflight")
	actor := flags.String("actor", "", "maintenance actor")
	reason := flags.String("reason", "", "maintenance reason")
	class := flags.String("class", reviewtransaction.CompactMalformedReasonHistoricalTerminalArtifacts, "classified anomaly")
	authorization := flags.String("maintainer-authorization", "", "exact authorization emitted by preflight")
	at := flags.String("quarantined-at", "", "optional RFC3339 audit time")
	if err := parseReviewFlags(flags, args); err != nil {
		return err
	}
	if reviewHelpRequested(args) {
		return nil
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected review quarantine-compact argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(*lineage) == "" || strings.TrimSpace(*actor) == "" || strings.TrimSpace(*reason) == "" {
		return errors.New("review quarantine-compact requires --lineage, --actor, and --reason")
	}
	if *preflight {
		if *repository != "" || *expectedSHA != "" || *revision != "" || *authorization != "" || *at != "" {
			return errors.New("review quarantine-compact --preflight rejects execution bindings")
		}
		assessment, request, err := reviewtransaction.PrepareCompactMalformedQuarantine(context.Background(), *cwd, *lineage, *actor, *reason)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(ReviewCompactQuarantineResult{Operation: "review/quarantine-compact", Assessment: &assessment, Request: &request})
	}
	var when time.Time
	var err error
	if *at != "" {
		when, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return errors.New("review quarantine-compact requires RFC3339 --quarantined-at")
		}
	}
	request := reviewtransaction.CompactMalformedQuarantineRequest{Repository: *repository, LineageID: *lineage, ExpectedStateSHA: *expectedSHA, ExpectedRevision: *revision, Actor: *actor, Reason: *reason, AnomalyClass: *class, Authorization: *authorization, QuarantinedAt: when}
	record, err := reviewtransaction.QuarantineMalformedCompact(context.Background(), *cwd, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(ReviewCompactQuarantineResult{Operation: "review/quarantine-compact", Record: &record})
}
