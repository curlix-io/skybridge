package mask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// MetricsRecorder is the subset of metrics.Recorder that maskers need, kept as a small local
// interface (rather than importing the metrics package's concrete type into every call site) so
// tests can inject a fake recorder and assert exactly what was recorded. A nil MetricsRecorder is
// always a safe no-op — every masker checks for nil before calling through it, mirroring how
// metrics.Recorder itself no-ops when unconfigured.
type MetricsRecorder interface {
	RecordAnalyzed(connectionKey, source string)
	RecordMasked(connectionKey, entityType string, byteCount int, source string)
}

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
	anonymizers  map[string]any
	// metrics records analyzed/masked outcome counts (pure metadata, never values) for the Data
	// Classification dashboard. Nil is a safe no-op — see MetricsRecorder's doc comment.
	metrics MetricsRecorder
	// connectionKey identifies this agent's connection (metrics.ConnectionKey's
	// "{driver}__{connectionRole}" format) for attributing metrics rows. Empty when metrics is nil.
	connectionKey string
	// state bundles the ad-hoc recognizers, entity allowlist, and score threshold behind a single
	// atomic pointer so a control-plane poller (see the agent's recognizers source) can hot-swap
	// all three together while sessions are in flight. A single bundled pointer (rather than three
	// separate atomics) guarantees a reader never observes a torn combination — e.g. new entities
	// paired with a stale score_threshold — which three independent atomics could allow between two
	// racing Store calls. Reads are lock-free via atomic.Pointer, mirroring mask.Overlay.
	state  atomic.Pointer[remoteState]
	strict bool
	http   *http.Client
}

// remoteState is the bundle of hot-swappable analyze() inputs. See Remote.state.
type remoteState struct {
	recognizers []any
	entities    []string
	// scoreThreshold uses noScoreThreshold as an explicit "unset" sentinel rather than the zero
	// value: 0.0 is a theoretically valid Presidio score_threshold (match everything), so the zero
	// value can't double as "don't send this field" the way it does for e.g. minLen/timeout above.
	// A negative sentinel keeps the field a plain float64 (no pointer/extra allocation) while
	// remaining unambiguous, since Presidio score thresholds are never negative.
	scoreThreshold float64
}

// noScoreThreshold is the "not configured" sentinel for RemoteConfig.ScoreThreshold and
// remoteState.scoreThreshold. See remoteState's doc comment for why a sentinel (vs. a *float64)
// was chosen.
const noScoreThreshold float64 = -1

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
	// AdHocRecognizers is Presidio's /analyze "ad_hoc_recognizers" array verbatim — pattern
	// recognizers defined per-request rather than baked into the analyzer image, so an org can add
	// its own PII types (e.g. an internal account-number format) without building a custom Presidio
	// image. See config.LoadRecognizersFile for how this is populated from a YAML file. Nil sends no
	// ad_hoc_recognizers field, matching Presidio's own default of none.
	AdHocRecognizers []any
	// ScoreThreshold sets Presidio's /analyze "score_threshold" (min confidence to report a match).
	// The zero value means "not configured" and omits the field from the request entirely, letting
	// Presidio fall back to each recognizer's own default threshold — see remoteState's doc comment
	// for why noScoreThreshold (not 0.0) is used internally as the sentinel once this is stored.
	ScoreThreshold float64
	// Strict, when true, makes MaskRow return ErrMaskerUnavailable instead of forwarding a value
	// unmasked when analyze/anonymize cannot be completed (transport error, non-200, malformed
	// response). Default (false) is best-effort: a masker outage never blocks the query.
	Strict  bool
	Timeout time.Duration
	// Metrics, when non-nil, records analyzed/masked outcome counts under ConnectionKey and source
	// "recognizer". Nil (default) records nothing — see MetricsRecorder's doc comment.
	Metrics MetricsRecorder
	// ConnectionKey identifies this agent's connection for Metrics (see metrics.ConnectionKey).
	// Only meaningful when Metrics is non-nil.
	ConnectionKey string
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
	threshold := noScoreThreshold
	if cfg.ScoreThreshold > 0 {
		threshold = cfg.ScoreThreshold
	}
	r := &Remote{
		analyzeURL:    cfg.AnalyzeURL,
		anonymizeURL:  cfg.AnonymizeURL,
		language:      lang,
		minLen:        minLen,
		anonymizers:   anonymizers,
		strict:        cfg.Strict,
		http:          &http.Client{Timeout: to},
		metrics:       cfg.Metrics,
		connectionKey: cfg.ConnectionKey,
	}
	r.state.Store(&remoteState{
		recognizers:    cfg.AdHocRecognizers,
		entities:       entities,
		scoreThreshold: threshold,
	})
	return r
}

// ReplaceConfig atomically swaps the active ad-hoc recognizer set, entity allowlist, and score
// threshold together. Safe to call concurrently with MaskRow/Detect. Used by a control-plane
// poller to hot-swap the whole analyze() configuration with no restart, and to guarantee a reader
// never observes entities/recognizers/threshold from two different poll cycles at once (see
// remoteState's doc comment). scoreThreshold <= 0 means "unset" — omit score_threshold from the
// Presidio request — matching RemoteConfig.ScoreThreshold's convention. A nil/empty entities slice
// falls back to defaultEntities, matching NewRemote's own construction-time behavior.
func (r *Remote) ReplaceConfig(recognizers []any, entities []string, scoreThreshold float64) {
	if len(entities) == 0 {
		entities = defaultEntities
	}
	threshold := noScoreThreshold
	if scoreThreshold > 0 {
		threshold = scoreThreshold
	}
	r.state.Store(&remoteState{
		recognizers:    recognizers,
		entities:       entities,
		scoreThreshold: threshold,
	})
}

func (r *Remote) currentState() *remoteState {
	if s := r.state.Load(); s != nil {
		return s
	}
	return &remoteState{entities: defaultEntities, scoreThreshold: noScoreThreshold}
}

func (r *Remote) currentRecognizers() []any {
	return r.currentState().recognizers
}

func (r *Remote) currentEntities() []string {
	return r.currentState().entities
}

func (r *Remote) currentScoreThreshold() float64 {
	return r.currentState().scoreThreshold
}

// Enabled reports whether the remote masking service is configured.
func (r *Remote) Enabled() bool { return r.analyzeURL != "" && r.anonymizeURL != "" }

// Detect runs analyze only (no anonymize) and reports the highest-confidence entity type found in
// text, if any. It is best-effort: a transport/decode failure or a clean "nothing found" result
// both report ok=false, indistinguishable to the caller — this is intentional, since a detection
// failure here should never propose a label, only a successful positive match should.
func (r *Remote) Detect(ctx context.Context, text string) (category string, confidence float64, ok bool) {
	if !r.Enabled() || len(text) < r.minLen {
		return "", 0, false
	}
	spans, failed := r.analyze(ctx, text)
	if failed || len(spans) == 0 {
		return "", 0, false
	}
	best := spans[0]
	for _, s := range spans[1:] {
		if s.Score > best.Score {
			best = s
		}
	}
	return best.EntityType, best.Score, true
}

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
		if i >= len(cols) || row[i] == nil || !cols[i].Text || !cols[i].FreeText {
			continue
		}
		if len(row[i]) < r.minLen {
			continue
		}
		// RecordAnalyzed fires once per eligible value entering analyze/anonymize, regardless of
		// outcome — a clean miss, a transport failure, and a successful redaction are all
		// "analyzed" here, per RecordAnalyzed's contract.
		if r.metrics != nil {
			r.metrics.RecordAnalyzed(r.connectionKey, "recognizer")
		}
		masked, spans, failed := r.anonymize(ctx, string(row[i]))
		if failed {
			if r.strict {
				return row, ErrMaskerUnavailable
			}
			continue
		}
		if len(spans) > 0 {
			row[i] = []byte(masked)
			if r.metrics != nil {
				for _, s := range spans {
					r.metrics.RecordMasked(r.connectionKey, s.EntityType, s.End-s.Start, "recognizer")
				}
			}
		}
	}
	return row, nil
}

// anonymize runs analyze -> anonymize for one value. Returns the anonymized text (or the original
// text if nothing was detected), the detected spans (empty when nothing was found), and
// failed=true only when the remote calls themselves could not be completed — never for a clean
// "no PII found" result. Callers must only treat the value as actually masked when failed is false
// AND spans is non-empty (a value can come back byte-identical to the input from anonymize even
// with spans, but an empty spans list unambiguously means nothing was masked).
func (r *Remote) anonymize(ctx context.Context, text string) (string, []detectedSpan, bool) {
	results, failed := r.analyze(ctx, text)
	if failed {
		return text, nil, true
	}
	if len(results) == 0 {
		return text, nil, false
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
		return text, nil, true
	}
	return out.Text, results, false
}

// analyze returns the detected spans and failed=true only on a transport/decode/non-200 error —
// an empty result slice with failed=false means the call succeeded and found nothing.
func (r *Remote) analyze(ctx context.Context, text string) ([]detectedSpan, bool) {
	body := map[string]any{"text": text, "language": r.language, "entities": r.currentEntities()}
	if recognizers := r.currentRecognizers(); len(recognizers) > 0 {
		body["ad_hoc_recognizers"] = recognizers
	}
	if threshold := r.currentScoreThreshold(); threshold != noScoreThreshold {
		body["score_threshold"] = threshold
	}
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
