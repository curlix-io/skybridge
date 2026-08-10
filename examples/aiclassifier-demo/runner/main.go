// Command aiclassifier-demo-runner drives internal/pathlabel/aiclassifier's real Scanner/LLM code
// against a stub LLM completion server (see ../stub_llm_server.py), and contrasts it with a
// simulated "today" baseline — mask.Remote's default, content-only, regex-based detection
// (internal/mask/remote.go's defaultEntities), gated on live query traffic the same way
// internal/edge/dbquery/mask.go's proposeLeaf is — to show what coverage the AI classifier adds on
// top of what Skybridge already does. Not a production entry point — see
// docs/AI_PATH_LABELLING_DESIGN.md for how a real deployment would wire a Sampler against an actual
// database instead of the fakeSampler below.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// fakeSampler stands in for a real read-only database scan (see aiclassifier.Sampler's doc
// comment) — this demo cares about showing the classifier/scanner/label.Store pipeline working
// end-to-end against a real (stubbed) HTTP backend, not about actually reading a database.
type fakeSampler struct {
	data map[string][]string
}

func (f *fakeSampler) Sample(_ context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool) {
	s, ok := f.data[objectID+"|"+fieldPath]
	if !ok {
		return nil, false
	}
	if len(s) > maxSamples {
		s = s[:maxSamples]
	}
	return s, true
}

// demoField is one fabricated column, plus whether it has ever received live query traffic —
// the dimension that decides whether today's baseline (traffic-driven, content-only) ever even
// gets a chance to look at it. The AI classifier scans by schema, not traffic, so it has no such
// gate — that asymmetry is the whole point of this demo.
type demoField struct {
	aiclassifier.Field
	Samples []string
	Queried bool
	Note    string
}

// baselineEmailRe/baselineSSNRe/baselinePhoneRe are simplified stand-ins for a few of
// mask.Remote's defaultEntities regexes (EMAIL_ADDRESS, US_SSN, PHONE_NUMBER) — not the real
// Presidio service, but the same category of signal: content shape only, never the field name.
var (
	baselineEmailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	baselineSSNRe   = regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)
	baselinePhoneRe = regexp.MustCompile(`^\d{3}-\d{3}-\d{4}$`)
)

// baselineDetect mirrors mask.Remote's Detect: a regex hit on a value's shape, never the column
// name. Matches mask.Remote.Detect's contract — no PII-shaped signal is indistinguishable from a
// detector failure, ok=false either way.
func baselineDetect(samples []string) (category string, ok bool) {
	for _, v := range samples {
		switch {
		case baselineEmailRe.MatchString(v):
			return "email_fields", true
		case baselineSSNRe.MatchString(v):
			return "ssn_fields", true
		case baselinePhoneRe.MatchString(v):
			return "phone_fields", true
		}
	}
	return "", false
}

func main() {
	endpoint := os.Getenv("STUB_LLM_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://stub-llm:8090"
	}

	fields := []demoField{
		{
			Field:   aiclassifier.Field{ObjectID: "org:pg:appdb:users", FieldPath: "email"},
			Samples: []string{"alice@example.com", "bob@example.com", "carol@example.com"},
			Queried: true,
			Note:    "queried table, content is email-shaped — baseline already handles this today",
		},
		{
			Field:   aiclassifier.Field{ObjectID: "org:pg:appdb:users", FieldPath: "ssn_last4"},
			Samples: []string{"6789", "4321", "0011"},
			Queried: true,
			Note:    "queried, but a bare 4-digit value has no PII shape — only the column name gives it away",
		},
		{
			Field:   aiclassifier.Field{ObjectID: "org:pg:appdb:users", FieldPath: "dob"},
			Samples: []string{"1990-05-14", "1985-11-02", "2001-07-30"},
			Queried: true,
			Note:    "queried, but a plain date has no default-entity regex match — DATE_TIME is opt-in/NER-only",
		},
		{
			Field:   aiclassifier.Field{ObjectID: "org:pg:appdb:archive_users", FieldPath: "email"},
			Samples: []string{"dana@example.com", "erin@example.com"},
			Queried: false,
			Note:    "genuinely PII, but this archive table has never been queried — baseline never runs at all",
		},
		{
			Field:   aiclassifier.Field{ObjectID: "org:pg:appdb:users", FieldPath: "display_name"},
			Samples: []string{"Alice", "Bob", "Carol"},
			Queried: true,
			Note:    "not PII in this taxonomy — both should correctly propose nothing",
		},
	}

	sampler := &fakeSampler{data: make(map[string][]string, len(fields))}
	for _, f := range fields {
		sampler.data[f.ObjectID+"|"+f.FieldPath] = f.Samples
	}

	classifier := aiclassifier.NewLLM(aiclassifier.LLMConfig{
		Endpoint:      endpoint,
		Categories:    []string{"email_fields", "ssn_fields", "phone_fields", "dob_fields", "none"},
		MinConfidence: 0.5,
		Timeout:       5 * time.Second,
	})

	ctx := context.Background()
	waitForStub(ctx, endpoint)

	// aiStore: the real Scanner/LLM code, run against every field regardless of Queried — this is
	// exactly what makes it independent of live traffic (docs/AI_PATH_LABELLING_DESIGN.md §2).
	aiStore := label.NewMemStore()
	aiFields := make([]aiclassifier.Field, len(fields))
	for i, f := range fields {
		aiFields[i] = f.Field
	}
	aiScanner := aiclassifier.NewScanner(aiclassifier.ScannerConfig{Classifier: classifier, Sampler: sampler, Store: aiStore})
	aiScanner.ScanFields(ctx, aiFields)

	// baselineStore: today's behavior — proposeLeaf-style, content-only, and only ever invoked for
	// a field that has actually been queried (Queried == true). A never-queried field simply never
	// gets a chance, exactly like a table nobody has run a query against yet.
	baselineStore := label.NewMemStore()
	for _, f := range fields {
		if !f.Queried {
			continue
		}
		if category, ok := baselineDetect(f.Samples); ok {
			_ = baselineStore.Put(ctx, label.Label{
				ObjectID: f.ObjectID, FieldPath: f.FieldPath, MatchMode: label.MatchPath,
				Category: category, Source: label.SourceProposed, Confidence: 1.0, SampleCount: len(f.Samples),
			})
		}
	}

	fmt.Println()
	fmt.Printf("%-28s %-8s %-16s %-16s %s\n", "FIELD", "QUERIED", "WITHOUT AI", "WITH AI", "WHY")
	fmt.Println("----------------------------------------------------------------------------------------------------------------")
	withoutCount, withCount := 0, 0
	for _, f := range fields {
		without := "no proposal"
		if l, ok, _ := baselineStore.Lookup(ctx, f.ObjectID, f.FieldPath); ok {
			without = l.Category
			withoutCount++
		}
		with := "no proposal"
		if l, ok, _ := aiStore.Lookup(ctx, f.ObjectID, f.FieldPath); ok {
			with = l.Category
			withCount++
		}
		queried := "no"
		if f.Queried {
			queried = "yes"
		}
		fmt.Printf("%-28s %-8s %-16s %-16s %s\n", f.ObjectID+"."+f.FieldPath, queried, without, with, f.Note)
	}

	fmt.Printf("\nWithout AI classifier: %d/%d fields covered (today's baseline — a human label, or\n", withoutCount, len(fields))
	fmt.Println("mask.Remote's content-only regex firing on traffic that happens to touch the field).")
	fmt.Printf("With AI classifier:    %d/%d fields covered (proposed from column name + samples,\n", withCount, len(fields))
	fmt.Println("independent of query traffic).")
	fmt.Println("\nEvery AI proposal above has Source=proposed — none of it redacts live traffic until a")
	fmt.Println("steward promotes it to manual/platform (PathOverlay's confirm gate is untouched).")
}

func waitForStub(ctx context.Context, endpoint string) {
	c := aiclassifier.NewLLM(aiclassifier.LLMConfig{Endpoint: endpoint, Categories: []string{"none"}, Timeout: 2 * time.Second})
	for i := 0; i < 30; i++ {
		if _, _, _, ok := c.Classify(ctx, "healthcheck", "healthcheck", []string{"ping"}); ok {
			return
		}
		time.Sleep(time.Second)
	}
	log.Printf("warning: stub LLM at %s did not respond to a health probe in time; proceeding anyway", endpoint)
}
