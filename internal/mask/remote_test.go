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
	cols := []Column{{Name: "email", Text: true, FreeText: true}}
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
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{{Name: "email", Text: true, FreeText: true}}
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
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, MinLen: 4})

	cols := []Column{{Name: "bin", Text: false}, {Name: "n", Text: true, FreeText: true}, {Name: "short", Text: true, FreeText: true}}
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
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})

	cols := []Column{{Name: "note", Text: true, FreeText: true}}
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
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
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
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
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
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 5, Score: 0.9}}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
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
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	row := [][]byte{[]byte("this value must not leak")}
	_, err := r.MaskRow(context.Background(), cols, row)
	if !errors.Is(err, ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable in strict mode, got %v", err)
	}
}

func TestRemoteStrictReturnsErrorOnAnonymizeFailure(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 5, Score: 0.9}}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL, Strict: true})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	row := [][]byte{[]byte("value that must not leak")}
	_, err := r.MaskRow(context.Background(), cols, row)
	if !errors.Is(err, ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable in strict mode, got %v", err)
	}
}

func TestRemoteStrictNoErrorWhenNothingDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL, Strict: true})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
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
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL, Strict: true})
	cols := []Column{{Name: "email", Text: true, FreeText: true}}
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
	entities := r.currentEntities()
	if len(entities) == 0 {
		t.Fatal("expected default entities to be set, got none")
	}
	for _, nerEntity := range []string{"PERSON", "LOCATION", "ORGANIZATION", "NRP"} {
		for _, e := range entities {
			if e == nerEntity {
				t.Fatalf("expected NER-backed entity %q to require opt-in, found in defaults %v", nerEntity, entities)
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
	got := r.currentEntities()
	if len(got) != 2 || got[0] != "EMAIL_ADDRESS" || got[1] != "PERSON" {
		t.Fatalf("expected explicit entities to be honored, got %v", got)
	}
	if _, ok := r.anonymizers["US_SSN"]; !ok {
		t.Fatalf("expected explicit anonymizers to be honored, got %v", r.anonymizers)
	}
}

func TestNewRemoteHonorsAllowList(t *testing.T) {
	r := NewRemote(RemoteConfig{
		AnalyzeURL:     "http://a",
		AnonymizeURL:   "http://b",
		AllowList:      []string{"support@example.com", "555-0100"},
		AllowListMatch: AllowListMatchRegex,
	})
	if len(r.allowList) != 2 || r.allowList[0] != "support@example.com" || r.allowList[1] != "555-0100" {
		t.Fatalf("expected explicit allow list to be honored, got %v", r.allowList)
	}
	if r.allowListMatch != AllowListMatchRegex {
		t.Fatalf("expected explicit allow list match to be honored, got %v", r.allowListMatch)
	}
}

func TestNewRemoteDefaultsAllowListMatchToExact(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://a", AnonymizeURL: "http://b", AllowList: []string{"support@example.com"}})
	if r.allowListMatch != AllowListMatchExact {
		t.Fatalf("expected AllowListMatch to default to exact, got %v", r.allowListMatch)
	}
}

func TestRemoteAnalyzeSendsConfiguredAllowList(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{
		AnalyzeURL:     analyzeSrv.URL,
		AnonymizeURL:   analyzeSrv.URL,
		AllowList:      []string{"support@example.com", "555-0100"},
		AllowListMatch: AllowListMatchExact,
	})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	got, ok := gotBody["allow_list"].([]any)
	if !ok || len(got) != 2 || got[0] != "support@example.com" || got[1] != "555-0100" {
		t.Fatalf("expected analyze request to carry configured allow_list, got %v", gotBody["allow_list"])
	}
	if match, ok := gotBody["allow_list_match"].(string); !ok || match != "exact" {
		t.Fatalf("expected analyze request to carry allow_list_match=exact, got %v", gotBody["allow_list_match"])
	}
}

func TestRemoteAnalyzeSendsRegexAllowListMatch(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{
		AnalyzeURL:     analyzeSrv.URL,
		AnonymizeURL:   analyzeSrv.URL,
		AllowList:      []string{`\d{3}-\d{4}`},
		AllowListMatch: AllowListMatchRegex,
	})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	if match, ok := gotBody["allow_list_match"].(string); !ok || match != "regex" {
		t.Fatalf("expected analyze request to carry allow_list_match=regex, got %v", gotBody["allow_list_match"])
	}
}

func TestRemoteAnalyzeOmitsAllowListWhenUnset(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["allow_list"]; ok {
		t.Fatalf("expected no allow_list field when unset, got %v", gotBody["allow_list"])
	}
	if _, ok := gotBody["allow_list_match"]; ok {
		t.Fatalf("expected no allow_list_match field when allow_list unset, got %v", gotBody["allow_list_match"])
	}
}

func TestRemoteAnalyzeSendsConfiguredEntities(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, Entities: []string{"EMAIL_ADDRESS", "US_SSN"}})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
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
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "US_SSN", Start: 0, End: 4, Score: 0.9}}})
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
	cols := []Column{{Name: "ssn", Text: true, FreeText: true}}
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

func TestRemoteAnalyzeSendsConfiguredAdHocRecognizers(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	recognizers := []any{map[string]any{"name": "AcmeAccountNumberRecognizer", "supported_entity": "ACME_ACCOUNT_NUMBER"}}
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, AdHocRecognizers: recognizers})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	got, ok := gotBody["ad_hoc_recognizers"].([]any)
	if !ok || len(got) != 1 {
		t.Fatalf("expected analyze request to carry configured ad_hoc_recognizers, got %v", gotBody["ad_hoc_recognizers"])
	}
}

func TestRemoteAnalyzeOmitsAdHocRecognizersWhenUnset(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["ad_hoc_recognizers"]; ok {
		t.Fatalf("expected no ad_hoc_recognizers field when unset, got %v", gotBody["ad_hoc_recognizers"])
	}
}

func TestRemoteReplaceConfigHotSwapsAdHocRecognizers(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}

	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["ad_hoc_recognizers"]; ok {
		t.Fatalf("expected no ad_hoc_recognizers before ReplaceConfig, got %v", gotBody["ad_hoc_recognizers"])
	}

	r.ReplaceConfig([]any{map[string]any{"name": "AcmeAccountNumberRecognizer"}}, nil, 0)

	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	got, ok := gotBody["ad_hoc_recognizers"].([]any)
	if !ok || len(got) != 1 {
		t.Fatalf("expected ad_hoc_recognizers after ReplaceConfig, got %v", gotBody["ad_hoc_recognizers"])
	}
}

func TestRemoteReplaceConfigHotSwapsEntitiesAndScoreThreshold(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reset per request: a bare Decode into an existing map only overwrites keys present in
		// this request's body, so a key omitted this time (e.g. score_threshold) would otherwise
		// keep the previous request's stale value instead of disappearing.
		gotBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}

	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["score_threshold"]; ok {
		t.Fatalf("expected no score_threshold before ReplaceConfig, got %v", gotBody["score_threshold"])
	}

	r.ReplaceConfig(nil, []string{"US_SSN"}, 0.8)

	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	entities, ok := gotBody["entities"].([]any)
	if !ok || len(entities) != 1 || entities[0] != "US_SSN" {
		t.Fatalf("expected hot-swapped entities after ReplaceConfig, got %v", gotBody["entities"])
	}
	if got := r.currentEntities(); len(got) != 1 || got[0] != "US_SSN" {
		t.Fatalf("expected currentEntities to reflect the hot-swapped value, got %v", got)
	}
	threshold, ok := gotBody["score_threshold"].(float64)
	if !ok || threshold != 0.8 {
		t.Fatalf("expected score_threshold 0.8 in request after ReplaceConfig, got %v", gotBody["score_threshold"])
	}

	// Swapping back to an unset threshold (<=0) must omit the field again, not send 0.
	r.ReplaceConfig(nil, []string{"US_SSN"}, 0)
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["score_threshold"]; ok {
		t.Fatalf("expected score_threshold omitted once unset again, got %v", gotBody["score_threshold"])
	}
}

func TestRemoteScoreThresholdFromConfigAppearsInRequest(t *testing.T) {
	var gotBody map[string]any
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, ScoreThreshold: 0.6})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
		t.Fatal(err)
	}
	got, ok := gotBody["score_threshold"].(float64)
	if !ok || got != 0.6 {
		t.Fatalf("expected score_threshold 0.6 seeded from RemoteConfig, got %v", gotBody["score_threshold"])
	}
}

// TestRemoteReplaceConfigConcurrentSwapsNeverTornRead exercises ReplaceConfig racing MaskRow —
// because the recognizers/entities/threshold live behind one atomic.Pointer swapped as a single
// struct, every read through currentState() sees a value from exactly one Store call, never a
// mix of fields from two different calls. This test can't directly observe a torn read (there
// isn't one, by construction) but it does prove the hot-swap is race-safe under `go test -race`
// and that analyze() always uses one consistent (entities, threshold) pair per call.
func TestRemoteReplaceConfigConcurrentSwapsNeverTornRead(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		entities, _ := body["entities"].([]any)
		threshold, hasThreshold := body["score_threshold"].(float64)
		// Only two configurations are ever stored below: (["A"], 0.1) and (["B"], 0.9). A torn read
		// would surface as some other combination, e.g. entities=["A"] with threshold=0.9.
		if len(entities) == 1 && entities[0] == "A" && hasThreshold && threshold != 0.1 {
			t.Errorf("torn read: entities=A but threshold=%v", threshold)
		}
		if len(entities) == 1 && entities[0] == "B" && hasThreshold && threshold != 0.9 {
			t.Errorf("torn read: entities=B but threshold=%v", threshold)
		}
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				r.ReplaceConfig(nil, []string{"A"}, 0.1)
			} else {
				r.ReplaceConfig(nil, []string{"B"}, 0.9)
			}
		}
	}()
	for i := 0; i < 200; i++ {
		if _, err := r.MaskRow(context.Background(), cols, [][]byte{[]byte("some text value")}); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

func TestRemoteMaskRowIndexOutOfRangeColsSkipped(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://unused", AnonymizeURL: "http://unused"})
	cols := []Column{{Name: "only-one", Text: true, FreeText: true}}
	row := [][]byte{[]byte("first"), []byte("second-has-no-column")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected row length preserved, got %d", len(out))
	}
}

// fakeMetricsRecorder is a small test double implementing MetricsRecorder — mirrors the
// seedSpyStore pattern in pathoverlay_test.go, recording every call's arguments for assertions.
type fakeMetricsRecorder struct {
	analyzed []string // connectionKey values passed to RecordAnalyzed
	masked   []fakeMaskedCall
}

type fakeMaskedCall struct {
	connectionKey string
	entityType    string
	byteCount     int
	source        string
}

func (f *fakeMetricsRecorder) RecordAnalyzed(connectionKey, source string) {
	f.analyzed = append(f.analyzed, connectionKey+"|"+source)
}

func (f *fakeMetricsRecorder) RecordMasked(connectionKey, entityType string, byteCount int, source string) {
	f.masked = append(f.masked, fakeMaskedCall{connectionKey, entityType, byteCount, source})
}

func TestRemoteMaskRowRecordsAnalyzedAndMaskedOnRedaction(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	fake := &fakeMetricsRecorder{}
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL, Metrics: fake, ConnectionKey: "postgres__primary"})
	cols := []Column{{Name: "email", Text: true, FreeText: true}}
	row := [][]byte{[]byte("alice@example.com")}
	if _, err := r.MaskRow(context.Background(), cols, row); err != nil {
		t.Fatal(err)
	}
	if len(fake.analyzed) != 1 || fake.analyzed[0] != "postgres__primary|recognizer" {
		t.Fatalf("expected one RecordAnalyzed call, got %+v", fake.analyzed)
	}
	if len(fake.masked) != 1 || fake.masked[0].entityType != "EMAIL_ADDRESS" || fake.masked[0].source != "recognizer" || fake.masked[0].byteCount != 17 {
		t.Fatalf("expected one RecordMasked call for EMAIL_ADDRESS/17 bytes, got %+v", fake.masked)
	}
}

func TestRemoteMaskRowRecordsAnalyzedOnlyWhenNoSpansDetected(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer analyzeSrv.Close()

	fake := &fakeMetricsRecorder{}
	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL, Metrics: fake, ConnectionKey: "postgres__primary"})
	cols := []Column{{Name: "note", Text: true, FreeText: true}}
	row := [][]byte{[]byte("nothing sensitive here")}
	if _, err := r.MaskRow(context.Background(), cols, row); err != nil {
		t.Fatal(err)
	}
	if len(fake.analyzed) != 1 {
		t.Fatalf("expected RecordAnalyzed called once even on a clean miss, got %+v", fake.analyzed)
	}
	if len(fake.masked) != 0 {
		t.Fatalf("expected no RecordMasked calls on a clean miss, got %+v", fake.masked)
	}
}

func TestRemoteDetectDisabledIsNoop(t *testing.T) {
	r := NewRemote(RemoteConfig{}) // no URLs configured
	category, confidence, ok := r.Detect(context.Background(), "alice@example.com")
	if ok || category != "" || confidence != 0 {
		t.Fatalf("expected Detect to no-op when disabled, got category=%q confidence=%v ok=%v", category, confidence, ok)
	}
}

func TestRemoteDetectSkipsShortText(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL, MinLen: 10})
	_, _, ok := r.Detect(context.Background(), "short")
	if ok {
		t.Fatal("expected Detect to report false for text shorter than MinLen")
	}
	if called {
		t.Fatal("expected analyze to never be called for text shorter than MinLen")
	}
}

func TestRemoteDetectReturnsHighestConfidenceSpan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{
			{EntityType: "PHONE_NUMBER", Start: 0, End: 5, Score: 0.4},
			{EntityType: "EMAIL_ADDRESS", Start: 6, End: 20, Score: 0.9},
			{EntityType: "US_SSN", Start: 21, End: 30, Score: 0.6},
		}})
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL})
	category, confidence, ok := r.Detect(context.Background(), "some sufficiently long text value")
	if !ok {
		t.Fatal("expected Detect to report ok=true when spans are found")
	}
	if category != "EMAIL_ADDRESS" || confidence != 0.9 {
		t.Fatalf("expected highest-confidence span EMAIL_ADDRESS/0.9, got %q/%v", category, confidence)
	}
}

func TestRemoteDetectReturnsFalseWhenNothingFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}})
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL})
	_, _, ok := r.Detect(context.Background(), "some sufficiently long text value")
	if ok {
		t.Fatal("expected Detect to report ok=false when analyze finds nothing")
	}
}

func TestRemoteDetectReturnsFalseOnTransportError(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://127.0.0.1:0", AnonymizeURL: "http://127.0.0.1:0"})
	category, confidence, ok := r.Detect(context.Background(), "some sufficiently long text value")
	// Detect is best-effort: a transport failure and a clean miss are both ok=false,
	// indistinguishable to the caller (see Detect's doc comment) — this must never surface an error.
	if ok || category != "" || confidence != 0 {
		t.Fatalf("expected Detect to fail closed on transport error, got category=%q confidence=%v ok=%v", category, confidence, ok)
	}
}

func TestRemoteCurrentStateFallsBackWhenNil(t *testing.T) {
	// currentState()'s nil-pointer fallback branch is only reachable if the atomic.Pointer was never
	// stored — NewRemote always stores one, so exercise the fallback via a zero-value Remote (state
	// atomic.Pointer left unset) to prove it never panics and returns usable defaults.
	var r Remote
	st := r.currentState()
	if st == nil {
		t.Fatal("expected a non-nil fallback state")
	}
	if len(st.entities) == 0 {
		t.Fatal("expected fallback state to carry defaultEntities")
	}
	if st.scoreThreshold != noScoreThreshold {
		t.Fatalf("expected fallback scoreThreshold to be unset, got %v", st.scoreThreshold)
	}
}

func TestRemotePostJSONFailsOnUnmarshalableBody(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://unused", AnonymizeURL: "http://unused"})
	var out any
	// A channel value can never be json.Marshal'd — exercises postJSON's json.Marshal error path.
	ok := r.postJSON(context.Background(), "http://unused", map[string]any{"bad": make(chan int)}, &out)
	if ok {
		t.Fatal("expected postJSON to report false when the request body cannot be marshaled")
	}
}

func TestRemotePostJSONFailsOnMalformedResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer srv.Close()
	r := NewRemote(RemoteConfig{AnalyzeURL: srv.URL, AnonymizeURL: srv.URL})
	var out []detectedSpan
	ok := r.postJSON(context.Background(), srv.URL, map[string]any{"text": "x"}, &out)
	if ok {
		t.Fatal("expected postJSON to report false when the response body is malformed JSON")
	}
}

func TestRemoteMaskRowBatchesMultipleColumnsIntoOneAnalyzeCall(t *testing.T) {
	var analyzeCalls int
	var gotTexts []string
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		analyzeCalls++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, t := range body["text"].([]any) {
			gotTexts = append(gotTexts, t.(string))
		}
		// Three inputs in, three (possibly empty) span lists out, in the same order.
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{}, {}, {}})
	}))
	defer analyzeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: analyzeSrv.URL})
	cols := []Column{
		{Name: "a", Text: true, FreeText: true},
		{Name: "bin", Text: false}, // excluded: not eligible
		{Name: "b", Text: true, FreeText: true},
		{Name: "c", Text: true, FreeText: true},
	}
	row := [][]byte{[]byte("first value"), []byte("skip me"), []byte("second value"), []byte("third value")}
	if _, err := r.MaskRow(context.Background(), cols, row); err != nil {
		t.Fatal(err)
	}
	if analyzeCalls != 1 {
		t.Fatalf("expected exactly one batched analyze call for the whole row, got %d", analyzeCalls)
	}
	want := []string{"first value", "second value", "third value"}
	if len(gotTexts) != len(want) {
		t.Fatalf("expected %d texts in the batch, got %v", len(want), gotTexts)
	}
	for i, w := range want {
		if gotTexts[i] != w {
			t.Fatalf("expected batch text[%d]=%q, got %q", i, w, gotTexts[i])
		}
	}
}

func TestRemoteMaskRowCorrelatesBatchSpansToCorrectColumn(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Column 0 (email) gets an EMAIL_ADDRESS span; column 1 (ssn) gets nothing.
		_ = json.NewEncoder(w).Encode([][]detectedSpan{
			{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}},
			{},
		})
	}))
	defer analyzeSrv.Close()
	var anonymizeCalls int
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anonymizeCalls++
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{
		{Name: "email", Text: true, FreeText: true},
		{Name: "ssn", Text: true, FreeText: true},
	}
	row := [][]byte{[]byte("alice@example.com"), []byte("not actually an ssn")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected column 0 (email) redacted, got %q", out[0])
	}
	if string(out[1]) != "not actually an ssn" {
		t.Fatalf("expected column 1 (ssn) untouched since its batch result had no spans, got %q", out[1])
	}
	if anonymizeCalls != 1 {
		t.Fatalf("expected anonymize called exactly once (only for the column with a detection), got %d", anonymizeCalls)
	}
}

func TestRemoteMaskRowAnonymizeCalledOncePerColumnWithSpans(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{
			{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 5, Score: 0.9}},
			{{EntityType: "US_SSN", Start: 0, End: 5, Score: 0.9}},
			{},
		})
	}))
	defer analyzeSrv.Close()
	var anonymizeCalls int
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anonymizeCalls++
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{
		{Name: "a", Text: true, FreeText: true},
		{Name: "b", Text: true, FreeText: true},
		{Name: "c", Text: true, FreeText: true},
	}
	row := [][]byte{[]byte("value a"), []byte("value b"), []byte("value c")}
	if _, err := r.MaskRow(context.Background(), cols, row); err != nil {
		t.Fatal(err)
	}
	if anonymizeCalls != 2 {
		t.Fatalf("expected anonymize called once per column with spans (2), got %d", anonymizeCalls)
	}
}

func TestRemoteMaskRowBatchAnalyzeTransportErrorLeavesRowUnchanged(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://127.0.0.1:0", AnonymizeURL: "http://127.0.0.1:0"})
	cols := []Column{
		{Name: "a", Text: true, FreeText: true},
		{Name: "b", Text: true, FreeText: true},
	}
	row := [][]byte{[]byte("first value stays"), []byte("second value stays")}
	out, err := r.MaskRow(context.Background(), cols, row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "first value stays" || string(out[1]) != "second value stays" {
		t.Fatalf("expected both values unchanged on batch analyze transport error, got %v", out)
	}
}

func TestRemoteMaskRowBatchAnalyzeTransportErrorStrictAbortsWholeRow(t *testing.T) {
	r := NewRemote(RemoteConfig{AnalyzeURL: "http://127.0.0.1:0", AnonymizeURL: "http://127.0.0.1:0", Strict: true})
	cols := []Column{
		{Name: "a", Text: true, FreeText: true},
		{Name: "b", Text: true, FreeText: true},
	}
	row := [][]byte{[]byte("first value"), []byte("second value")}
	_, err := r.MaskRow(context.Background(), cols, row)
	if !errors.Is(err, ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable in strict mode on batch analyze failure, got %v", err)
	}
}

func TestRemoteMaskRowNilMetricsIsNoop(t *testing.T) {
	analyzeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([][]detectedSpan{{{EntityType: "EMAIL_ADDRESS", Start: 0, End: 17, Score: 0.9}}})
	}))
	defer analyzeSrv.Close()
	anonymizeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "[redacted]"})
	}))
	defer anonymizeSrv.Close()

	r := NewRemote(RemoteConfig{AnalyzeURL: analyzeSrv.URL, AnonymizeURL: anonymizeSrv.URL})
	cols := []Column{{Name: "email", Text: true, FreeText: true}}
	row := [][]byte{[]byte("alice@example.com")}
	if _, err := r.MaskRow(context.Background(), cols, row); err != nil {
		t.Fatal(err)
	}
}
