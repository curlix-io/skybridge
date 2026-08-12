package mask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// maxPresidioResponseBytes bounds how much of an analyze/anonymize response postJSON will buffer.
// A compromised or MITM'd Presidio endpoint could otherwise stream an effectively unbounded (or
// slow-drip) response body — http.Client.Timeout bounds the whole round trip's wall-clock time, but
// not how many bytes a sufficiently-fast-but-huge body delivers within that window. Generous enough
// for a heavily batched analyze call (many texts, many spans each) while still bounding the worst
// case, matching the same-shaped cap already used for control-plane responses elsewhere (see
// internal/agent/overlay_source.go, recognizers_source.go, internal/pathlabel/remotestore.go).
const maxPresidioResponseBytes = 10 << 20

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
// MaskRow batches every eligible column's text into a single "analyze" call per row (Presidio's
// stock analyzer server accepts "text" as a JSON array and returns one span list per input in the
// same order — see analyzeBatch), then calls "anonymize" once per column that actually had a
// detection (Presidio's anonymizer has no batch input, so that half stays one call per hit).
// RemoteConfig.AllowList lets an operator suppress specific known-safe values/patterns from ever
// being reported as a detection in the first place.
//
// It is best-effort: a detection miss or transport error never fails the session; the value is
// forwarded unchanged. The masker is a no-op when the analyze/anonymize URLs are empty.
type Remote struct {
	analyzeURL   string
	anonymizeURL string
	language     string
	minLen       int
	anonymizers  map[string]any
	// allowList/allowListMatch are Presidio's /analyze "allow_list"/"allow_list_match" — construction-
	// time only, like anonymizers, since there's no control-plane dynamic-source equivalent for this
	// yet (unlike entities/recognizers/threshold, which live in remoteState for hot-swapping).
	allowList      []string
	allowListMatch AllowListMatch
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

// AllowListMatch selects how RemoteConfig.AllowList entries are interpreted by Presidio's
// /analyze "allow_list_match" — see RemoteConfig.AllowListMatch.
type AllowListMatch string

const (
	// AllowListMatchExact suppresses a detection only when it exactly matches an AllowList entry.
	// Presidio's own default.
	AllowListMatchExact AllowListMatch = "exact"
	// AllowListMatchRegex treats every AllowList entry as a regex pattern; a detection matching any
	// of them is suppressed.
	AllowListMatchRegex AllowListMatch = "regex"
)

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
	// AllowList is Presidio's /analyze "allow_list" — literal values or regex patterns (per
	// AllowListMatch) that should never be reported as PII, letting an operator suppress a known-safe
	// recurring false positive (e.g. a support line's own phone number, a fixture SSN in a staging
	// environment) without disabling an entire entity type or writing a custom recognizer. Nil sends
	// no allow_list field, matching Presidio's own default of none.
	AllowList []string
	// AllowListMatch is Presidio's /analyze "allow_list_match": AllowListMatchExact (default) or
	// AllowListMatchRegex. Meaningless when AllowList is empty.
	AllowListMatch AllowListMatch
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
	allowListMatch := cfg.AllowListMatch
	if allowListMatch == "" {
		allowListMatch = AllowListMatchExact
	}
	r := &Remote{
		analyzeURL:     cfg.AnalyzeURL,
		anonymizeURL:   cfg.AnonymizeURL,
		language:       lang,
		minLen:         minLen,
		anonymizers:    anonymizers,
		allowList:      cfg.AllowList,
		allowListMatch: allowListMatch,
		strict:         cfg.Strict,
		http:           &http.Client{Timeout: to},
		metrics:        cfg.Metrics,
		connectionKey:  cfg.ConnectionKey,
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
	results, failed := r.analyzeBatch(ctx, []string{text})
	if failed || len(results) == 0 || len(results[0]) == 0 {
		return "", 0, false
	}
	spans := results[0]
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

// MaskRow implements Masker by anonymizing each eligible text value. Every eligible column's text
// is analyzed in a single batched "analyze" call (see analyzeBatch); anonymize is then called once
// per column that actually had a detection. In strict mode (r.strict) a masker failure (transport
// error, non-200, malformed response) returns ErrMaskerUnavailable instead of forwarding the
// row unmasked; a successful call that simply finds nothing to mask is never an error, in either
// mode. A failed batch analyze call is one failure for the whole row (every eligible column shares
// the same outcome), rather than independently per column as when each column called analyze on
// its own — these calls hit the same backing service, so a real outage was already effectively
// correlated across columns in practice.
func (r *Remote) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	if !r.Enabled() {
		return row, nil
	}
	var eligible []int
	var texts []string
	for i := range row {
		if i >= len(cols) || row[i] == nil || !cols[i].Text || !cols[i].FreeText {
			continue
		}
		if len(row[i]) < r.minLen {
			continue
		}
		eligible = append(eligible, i)
		texts = append(texts, string(row[i]))
	}
	if len(eligible) == 0 {
		return row, nil
	}
	// RecordAnalyzed fires once per eligible value entering analyze/anonymize, regardless of
	// outcome — a clean miss, a transport failure, and a successful redaction are all "analyzed"
	// here, per RecordAnalyzed's contract.
	if r.metrics != nil {
		for range eligible {
			r.metrics.RecordAnalyzed(r.connectionKey, "recognizer")
		}
	}
	results, failed := r.analyzeBatch(ctx, texts)
	if failed {
		if r.strict {
			return row, ErrMaskerUnavailable
		}
		return row, nil
	}
	for j, i := range eligible {
		spans := results[j]
		if len(spans) == 0 {
			continue
		}
		masked, ok := r.anonymizeSpans(ctx, texts[j], spans)
		if !ok {
			if r.strict {
				return row, ErrMaskerUnavailable
			}
			continue
		}
		row[i] = []byte(masked)
		if r.metrics != nil {
			for _, s := range spans {
				r.metrics.RecordMasked(r.connectionKey, s.EntityType, s.End-s.Start, "recognizer")
			}
		}
	}
	return row, nil
}

// anonymizeSpans calls "anonymize" for one value given its already-known analyzer_results.
// Returns ok=false only when the remote call itself could not be completed (transport error,
// non-200, malformed response) — callers must leave the original value in place in that case.
func (r *Remote) anonymizeSpans(ctx context.Context, text string, spans []detectedSpan) (string, bool) {
	body := map[string]any{
		"text":             text,
		"analyzer_results": spans,
		"anonymizers":      r.anonymizers,
	}
	var out struct {
		Text string `json:"text"`
	}
	if !r.postJSON(ctx, r.anonymizeURL, body, &out) {
		return text, false
	}
	return out.Text, true
}

// analyzeBatch analyzes texts in a single "analyze" call. "text" is always sent as a JSON array
// (even for a length-1 slice) since Presidio's stock analyzer server branches its response shape
// on whether the request's "text" field is a list: an array in means an array of per-item span
// lists comes back, in the same order as texts — see presidio-analyzer's app.py. failed=true only
// on a transport/decode/non-200 error; a successful call always returns len(results) ==
// len(texts), each entry possibly empty when nothing was found for that text.
func (r *Remote) analyzeBatch(ctx context.Context, texts []string) ([][]detectedSpan, bool) {
	body := map[string]any{"text": texts, "language": r.language, "entities": r.currentEntities()}
	if recognizers := r.currentRecognizers(); len(recognizers) > 0 {
		body["ad_hoc_recognizers"] = recognizers
	}
	if threshold := r.currentScoreThreshold(); threshold != noScoreThreshold {
		body["score_threshold"] = threshold
	}
	if len(r.allowList) > 0 {
		body["allow_list"] = r.allowList
		body["allow_list_match"] = r.allowListMatch
	}
	var out [][]detectedSpan
	if !r.postJSON(ctx, r.analyzeURL, body, &out) || len(out) != len(texts) {
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
	limited := io.LimitReader(resp.Body, maxPresidioResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) > maxPresidioResponseBytes {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}
