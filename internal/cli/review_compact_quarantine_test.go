package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestReviewCompactQuarantineCLIRequiresAuditableInputs(t *testing.T) {
	var output bytes.Buffer
	err := RunReviewCompactQuarantine([]string{"--lineage", "synthetic"}, &output)
	if err == nil || !strings.Contains(err.Error(), "--actor") || !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("error=%v output=%s", err, output.String())
	}
}

func TestReviewCompactQuarantineCLIHelpIsNative(t *testing.T) {
	var output bytes.Buffer
	if err := RunReview([]string{"quarantine-compact", "--help"}, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--preflight", "--maintainer-authorization", "--expected-state-sha256", "--expected-revision"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("help missing %s:\n%s", want, output.String())
		}
	}
}
