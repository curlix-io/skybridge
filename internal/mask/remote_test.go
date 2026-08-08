package mask

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewRemoteAppliesDefaults(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://analyze", AnonymizeURL: "http://anonymize"})
	if r.language != "en" {
		t.Fatalf("expected default language 'en', got %q", r.language)
	}
	if r.minLen != 4 {
		t.Fatalf("expected default minLen 4, got %d", r.minLen)
	}
	if r.http.Timeout != 3*time.Second {
		t.Fatalf("expected default timeout 3s, got %v", r.http.Timeout)
	}
}

func TestNewRemoteHonorsExplicitConfig(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://a", AnonymizeURL: "http://b", Language: "fr", MinLen: 10, Timeout: 5 * time.Second})
	if r.language != "fr" || r.minLen != 10 || r.http.Timeout != 5*time.Second {
		t.Fatalf("unexpected config: lang=%q minLen=%d timeout=%v", r.language, r.minLen, r.http.Timeout)
	}
}

func TestRemoteEnabledRequiresBothURLs(t *testing.T) {
	cases := []struct {
		analyze, anonymize string
		want               bool
	}{
		{"", "", false},
		{"http://a", "", false},
		{"", "http://b", false},
		{"http://a", "http://b", true},
	}
	for _, c := range cases {
		r := NewRemote(RemoteConfig{AnalyzeURL: c.analyze, AnonymizeURL: c.anonymize})
		if got := r.Enabled(); got != c.want {
			t.Errorf("Enabled() with analyze=%q anonymize=%q = %v, want %v", c.analyze, c.anonymize, got, c.want)
		}
	}
}

func TestRemoteMaskRowNoopWhenDisabled(t *testing.T) {
	r := NewRemote(RemoteConfig{})
	cols := []Column{{Name: "email", Text: true}}
	row := [][]byte{[]byte("alice@example.com")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "alice@example.com" {
		t.Fatalf("expected row unchanged when disabled, got %q", out[0])
	}
}

func TestRemoteMaskRowRedactsDetectedText(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{{Name: "email", Text: true}}
	row := [][]byte{[]byte("alice@example.com")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected redacted value, got %q", out[0])
	}
}

func TestRemoteMaskRowSkipsNonTextAndNilAndShortValues(t *testing.T) {
	called := false
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_ = json.NewEncoder(w).Encode([]detectedSpan{})
	}))
	defer analyzeSrv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, MinLen: 4})

	cols := []Column{{Name: "bin", Text: false}, {Name: "n", Text: true}, {Name: "short", Text: true}}
	row := [][]byte{[]byte("binary-ish"), nil, []byte("abc")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "binary-ish" || out[1] != nil || string(out[2]) != "abc" {
		t.Fatalf("expected all values untouched, got %v", out)
	}
	if called {
		t.Fatal("expected analyze to never be called for non-text/nil/short values")
	}
}

func TestRemoteMaskRowKeepsOriginalWhenNoSpansDetected(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{})
	}))
	defer analyzeSrv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})

	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("nothing sensitive here")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "nothing sensitive here" {
		t.Fatalf("expected value unchanged when no spans detected, got %q", out[0])
	}
}

func TestRemoteMaskRowKeepsOriginalOnAnalyzeTransportError(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://127.0.0.1:0", AnonymizeURL: "http://127.0.0.1:0"})
	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("this value stays as-is")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "this value stays as-is" {
		t.Fatalf("expected value unchanged on transport error, got %q", out[0])
	}
}

func TestRemoteMaskRowKeepsOriginalOnAnalyzeNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL})
	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("unaffected value")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "unaffected value" {
		t.Fatalf("expected value unchanged on non-OK analyze response, got %q", out[0])
	}
}

func TestRemoteMaskRowKeepsOriginalOnAnonymizeFailure(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 5, Score: 0.9}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("value that stays put")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "value that stays put" {
		t.Fatalf("expected value unchanged when anonymize fails, got %q", out[0])
	}
}

func TestRemoteStrictReturnsErrorOnAnalyzeTransportError(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://127.0.0.1:0", AnonymizeURL: "http://127.0.0.1:0", Strict: true})
	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("this value must not leak")}
	_, err := r.MaskRow(context.Background(), cols, row)
	if !errors.Is(err, ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable in strict mode, got %v", err)
	}
}

func TestRemoteStrictReturnsErrorOnAnonymizeFailure(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 5, Score: 0.9}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL, Strict: true})
	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("value that must not leak")}
	_, err := r.MaskRow(context.Background(), cols, row)
	if !errors.Is(err, ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable in strict mode, got %v", err)
	}
}

func TestRemoteStrictNoErrorWhenNothingDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{})
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL, Strict: true})
	cols := []Column{{Name: "note", Text: true}}
	row := [][]byte{[]byte("nothing sensitive here")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatalf("clean 'nothing detected' result must not be an error even in strict mode: %v", err)
	}
	if string(out[0]) != "nothing sensitive here" {
		t.Fatalf("expected value unchanged, got %q", out[0])
	}
}

func TestRemoteStrictMasksSuccessfullyLikeBestEffort(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL, Strict: true})
	cols := []Column{{Name: "email", Text: true}}
	row := [][]byte{[]byte("alice@example.com")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected redacted value, got %q", out[0])
	}
}

func TestNewRemoteDefaultsToLowCostEntitiesAndReplaceAnonymizer(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://a", AnonymizeURL: "http://b"})
	if len(r.entities) == 0 {
		t.Fatal("expected default entities to be set, got none")
	}
	for _, nerEntity := range []string{"PERSON", "LOCATION", "ORGANIZATION", "NRP"} {
		for _, e := range r.entities {
			if e == nerEntity {
				t.Fatalf("expected NER-backed entity %q to require opt-in, found in defaults %v", nerEntity, r.entities)
			}
		}
	}
	def, ok := r.anonymizers["DEFAULT"].(map[string]any)
	if !ok || def["type"] != "replace" {
		t.Fatalf("expected default DEFAULT replace anonymizer, got %v", r.anonymizers)
	}
}

func TestNewRemoteHonorsExplicitEntitiesAndAnonymizers(t *testing.T) {
	entities := []string{"EMAIL_ADDRESS", "PERSON"}
	anonymizers := map[string]any{"US_SSN": map[string]any{"type": "mask", "masking_char": "*", "chars_to_mask": 5, "from_end": false}}
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://a", AnonymizeURL: "http://b", Entities: entities, Anonymizers: anonymizers})
	if len(r.entities) != 2 || r.entities[0] != "EMAIL_ADDRESS" || r.entities[1] != "PERSON" {
		t.Fatalf("expected explicit entities to be honored, got %v", r.entities)
	}
	if _, ok := r.anonymizers["US_SSN"]; !ok {
		t.Fatalf("expected explicit anonymizers to be honored, got %v", r.anonymizers)
	}
}

func TestRemoteAnalyzeSendsConfiguredEntities(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([]detectedSpan{})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, Entities: []string{"EMAIL_ADDRESS", "US_SSN"}})
	cols := []Column{{Name: "note", Text: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	got, ok := gotBody["entities"].([]any)
	if !ok || len(got) != 2 || got[0] != "EMAIL_ADDRESS" || got[1] != "US_SSN" {
		t.Fatalf("expected analyze request to carry configured entities, got %v", gotBody["entities"])
	}
}

func TestRemoteAnonymizeSendsConfiguredAnonymizers(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]detectedSpan{{EntityType: "US_SSN", Start: 0, End: 4, Score: 0.9}})
	}))
	defer analyzeSrv.Close()
	var gotBody map[string]any
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "***-1234"})
	}))
	defer anonymizeSrv.Close()

	anonymizers := map[string]any{"US_SSN": map[string]any{"type": "mask", "masking_char": "*", "chars_to_mask": 5}}
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL, Anonymizers: anonymizers})
	cols := []Column{{Name: "ssn", Text: true}}
	out, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("123-45-1234")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "***-1234" {
		t.Fatalf("expected partial mask output, got %q", out[0])
	}
	got, ok := gotBody["anonymizers"].(map[string]any)
	if !ok {
		t.Fatalf("expected anonymizers object in request, got %v", gotBody["anonymizers"])
	}
	if _, ok := got["US_SSN"]; !ok {
		t.Fatalf("expected US_SSN strategy to be sent, got %v", got)
	}
}

func TestRemoteMaskRowIndexOutOfRangeColsSkipped(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://unused", AnonymizeURL: "http://unused"})
	cols := []Column{{Name: "only-one", Text: true}}
	row := [][]byte{[]byte("first"), []byte("second-has-no-column")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected row length preserved, got %d", len(out))
	}
}
