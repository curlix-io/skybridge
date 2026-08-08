package mask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Remote is the default masker. It calls an external PII detection/anonymization HTTP service
// (an "analyze" endpoint that returns detected spans and an "anonymize" endpoint that rewrites
// them) to redact sensitive values in text fields. Any service that implements these two JSON
// endpoints can be used.
//
// It is best-effort: a detection miss or transport error never fails the session; the value is
// forwarded unchanged. The masker is a no-op when the analyze/anonymize URLs are empty.
type Remote struct {
	analyzeURL   string
	anonymizeURL string
	language     string
	minLen       int
	entities     []string
	anonymizers  map[string]any
	strict       bool
	http         *http.Client
}

// ErrMaskerUnavailable is returned by MaskRow (strict mode only) when the remote analyze/anonymize
// service could not be reached or returned an unusable response for a value that needed masking.
var ErrMaskerUnavailable = errors.New("mask: remote masking service unavailable")

// RemoteConfig configures the remote masking service client.
type RemoteConfig struct {
	AnalyzeURL   string // e.g. http://127.0.0.1:3000/analyze
	AnonymizeURL string // e.g. http://127.0.0.1:3001/anonymize
	Language     string // default "en"
	MinLen       int    // skip values shorter than this (numbers/short codes); default 4
	// Entities restricts detection to these Presidio entity types. Nil/empty falls back to
	// defaultEntities (regex/rule-based only) instead of Presidio's default of every registered
	// recognizer — the NER-backed types (PERSON, LOCATION, ORGANIZATION, NRP) are expensive and
	// prone to false positives on ordinary business data, so they require an explicit opt-in.
	Entities []string
	// Anonymizers is Presidio's /anonymize "anonymizers" object, keyed by entity type (or
	// "DEFAULT"), letting each type get its own strategy (redact, partial mask, hash, ...). Nil
	// falls back to a single DEFAULT replace-with-"[redacted]" rule.
	Anonymizers map[string]any
	// Strict, when true, makes MaskRow return ErrMaskerUnavailable instead of forwarding a value
	// unmasked when analyze/anonymize cannot be completed (transport error, non-200, malformed
	// response). Default (false) is best-effort: a masker outage never blocks the query.
	Strict  bool
	Timeout time.Duration
}

// defaultEntities are the regex/rule-based Presidio recognizers — a few ms of CPU each, no spaCy
// model involved — used when RemoteConfig.Entities is not set. NER-backed types are opt-in only.
var defaultEntities = []string{
	"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IP_ADDRESS", "IBAN_CODE", "CRYPTO",
}

// defaultAnonymizer replaces any detected span with a fixed placeholder, applied to every entity
// type unless RemoteConfig.Anonymizers overrides it.
var defaultAnonymizer = map[string]any{"DEFAULT": map[string]any{"type": "replace", "new_value": "[redacted]"}}

// NewRemote builds a remote masker. If cfg.AnalyzeURL is empty the masker is a no-op.
func NewRemote(cfg RemoteConfig) *Remote {
	lang := cfg.Language
	if lang == "" {
		lang = "en"
	}
	minLen := cfg.MinLen
	if minLen <= 0 {
		minLen = 4
	}
	to := cfg.Timeout
	if to <= 0 {
		to = 3 * time.Second
	}
	entities := cfg.Entities
	if len(entities) == 0 {
		entities = defaultEntities
	}
	anonymizers := cfg.Anonymizers
	if len(anonymizers) == 0 {
		anonymizers = defaultAnonymizer
	}
	return &Remote{
		analyzeURL:   cfg.AnalyzeURL,
		anonymizeURL: cfg.AnonymizeURL,
		language:     lang,
		minLen:       minLen,
		entities:     entities,
		anonymizers:  anonymizers,
		strict:       cfg.Strict,
		http:         &http.Client{Timeout: to},
	}
}

// Enabled reports whether the remote masking service is configured.
func (r *Remote) Enabled() bool { return r.analyzeURL != "" && r.anonymizeURL != "" }

type detectedSpan struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

// MaskRow implements Masker by anonymizing each eligible text value. In strict mode (r.strict) a
// masker failure (transport error, non-200, malformed response) returns ErrMaskerUnavailable
// instead of forwarding the value unmasked; a successful call that simply finds nothing to mask is
// never an error, in either mode.
func (r *Remote) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	if !r.Enabled() {
		return row, nil
	}
	for i := range row {
		if i >= len(cols) || row[i] == nil || !cols[i].Text {
			continue
		}
		if len(row[i]) < r.minLen {
			continue
		}
		masked, failed := r.anonymize(ctx, string(row[i]))
		if failed {
			if r.strict {
				return row, ErrMaskerUnavailable
			}
			continue
		}
		row[i] = []byte(masked)
	}
	return row, nil
}

// anonymize runs analyze -> anonymize for one value. Returns the anonymized text (or the original
// text if nothing was detected) and failed=true only when the remote calls themselves could not be
// completed — never for a clean "no PII found" result.
func (r *Remote) anonymize(ctx context.Context, text string) (string, bool) {
	results, failed := r.analyze(ctx, text)
	if failed {
		return text, true
	}
	if len(results) == 0 {
		return text, false
	}
	body := map[string]any{
		"text":             text,
		"analyzer_results": results,
		"anonymizers":      r.anonymizers,
	}
	var out struct {
		Text string `json:"text"`
	}
	if !r.postJSON(ctx, r.anonymizeURL, body, &out) {
		return text, true
	}
	return out.Text, false
}

// analyze returns the detected spans and failed=true only on a transport/decode/non-200 error —
// an empty result slice with failed=false means the call succeeded and found nothing.
func (r *Remote) analyze(ctx context.Context, text string) ([]detectedSpan, bool) {
	body := map[string]any{"text": text, "language": r.language, "entities": r.entities}
	var out []detectedSpan
	if !r.postJSON(ctx, r.analyzeURL, body, &out) {
		return nil, true
	}
	return out, false
}

func (r *Remote) postJSON(ctx context.Context, url string, body any, out any) bool {
	buf, err := json.Marshal(body)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(out) == nil
}
