package mask

import (
	"bytes"
	"context"
	"encoding/json"
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
	http         *http.Client
}

// RemoteConfig configures the remote masking service client.
type RemoteConfig struct {
	AnalyzeURL   string // e.g. http://127.0.0.1:3000/analyze
	AnonymizeURL string // e.g. http://127.0.0.1:3001/anonymize
	Language     string // default "en"
	MinLen       int    // skip values shorter than this (numbers/short codes); default 4
	Timeout      time.Duration
}

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
	return &Remote{
		analyzeURL:   cfg.AnalyzeURL,
		anonymizeURL: cfg.AnonymizeURL,
		language:     lang,
		minLen:       minLen,
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

// MaskRow implements Masker by anonymizing each eligible text value.
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
		masked, ok := r.anonymize(ctx, string(row[i]))
		if ok {
			row[i] = []byte(masked)
		}
	}
	return row, nil
}

// anonymize runs analyze -> anonymize for one value. Returns (text, true) on success; on any error
// it returns ("", false) so the caller keeps the original value (best-effort masking).
func (r *Remote) anonymize(ctx context.Context, text string) (string, bool) {
	results, ok := r.analyze(ctx, text)
	if !ok || len(results) == 0 {
		return "", false
	}
	body := map[string]any{
		"text":             text,
		"analyzer_results": results,
		"anonymizers":      map[string]any{"DEFAULT": map[string]any{"type": "replace", "new_value": "[redacted]"}},
	}
	var out struct {
		Text string `json:"text"`
	}
	if !r.postJSON(ctx, r.anonymizeURL, body, &out) {
		return "", false
	}
	return out.Text, true
}

func (r *Remote) analyze(ctx context.Context, text string) ([]detectedSpan, bool) {
	body := map[string]any{"text": text, "language": r.language}
	var out []detectedSpan
	if !r.postJSON(ctx, r.analyzeURL, body, &out) {
		return nil, false
	}
	return out, true
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
