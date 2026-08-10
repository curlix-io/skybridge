package aiclassifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LLM is a Classifier backend that prompts an LLM API with a field's identity and sampled values,
// constrained to a fixed taxonomy, and requires a structured JSON response — see
// docs/AI_PATH_LABELLING_DESIGN.md §5.1a. It speaks a minimal, provider-agnostic shape: POST a
// prompt string to a single completion endpoint, expect a JSON object body back. Any provider
// reachable behind that shape (a direct model API, or a proxy/gateway in front of one) works
// without a provider-specific SDK dependency, mirroring how mask.Remote treats Presidio as "any
// service that implements these two JSON endpoints" rather than binding to one vendor's client.
type LLM struct {
	endpoint   string
	apiKey     string
	categories []string
	minSamples int
	http       *http.Client
	minScore   float64
}

// LLMConfig configures an LLM classifier.
type LLMConfig struct {
	// Endpoint is a completion API that accepts {"prompt": "..."} and returns
	// {"category": "...", "profile": "...", "confidence": 0.0, "rationale": "..."} as its JSON
	// body — see completionResponse. Point this at a direct provider endpoint or an internal
	// gateway that adapts to this shape; LLM itself has no provider-specific knowledge.
	Endpoint string
	// APIKey, if set, is sent as a Bearer token. Empty is valid for an internal gateway that
	// authenticates some other way.
	APIKey string
	// Categories is the fixed taxonomy the model is constrained to — it must match label.Label's
	// Category values this deployment actually uses for confirmed labels, so a proposal is never
	// stuck in a category no steward-facing UI recognizes. Required; NewLLM panics if empty.
	Categories []string
	// MinSamples is the fewest sample values Classify will send to the model; fewer than this and
	// Classify reports ok=false rather than guessing from too little signal. Default 1.
	MinSamples int
	// MinConfidence discards a model response below this score rather than proposing a low-value
	// label.Store entry a steward would almost certainly reject. Default 0 (accept anything the
	// model returns) — set this per docs/AI_PATH_LABELLING_DESIGN.md §8 item 2's open question
	// once real proposal-quality data exists.
	MinConfidence float64
	Timeout       time.Duration
}

// completionResponse is the structured JSON body Endpoint must return. Rationale is accepted but
// not currently surfaced anywhere (label.Label has no free-text field yet — see
// docs/AI_PATH_LABELLING_DESIGN.md §5.4); kept here so a future schema addition doesn't require an
// endpoint contract change.
type completionResponse struct {
	Category   string  `json:"category"`
	Profile    string  `json:"profile"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// NewLLM builds an LLM classifier. Panics if cfg.Endpoint or cfg.Categories is empty — both are
// required for the classifier to produce a usable proposal at all, so failing fast at construction
// is preferable to a runtime nil/empty check on every Classify call.
func NewLLM(cfg LLMConfig) *LLM {
	if cfg.Endpoint == "" {
		panic("aiclassifier: NewLLM requires a non-empty Endpoint")
	}
	if len(cfg.Categories) == 0 {
		panic("aiclassifier: NewLLM requires a non-empty Categories taxonomy")
	}
	minSamples := cfg.MinSamples
	if minSamples <= 0 {
		minSamples = 1
	}
	to := cfg.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	return &LLM{
		endpoint:   cfg.Endpoint,
		apiKey:     cfg.APIKey,
		categories: cfg.Categories,
		minSamples: minSamples,
		minScore:   cfg.MinConfidence,
		http:       &http.Client{Timeout: to},
	}
}

// Classify implements Classifier. It is best-effort: a transport error, non-200 response,
// malformed JSON, a category outside the configured taxonomy, or a confidence below MinConfidence
// all report ok=false — indistinguishable to the caller, matching mask.Remote.Detect's contract
// that a classification failure must never itself become a proposal.
func (c *LLM) Classify(ctx context.Context, objectID, fieldPath string, samples []string) (category, profile string, confidence float64, ok bool) {
	if len(samples) < c.minSamples {
		return "", "", 0, false
	}
	resp, failed := c.complete(ctx, c.buildPrompt(objectID, fieldPath, samples))
	if failed {
		return "", "", 0, false
	}
	if !c.isKnownCategory(resp.Category) {
		return "", "", 0, false
	}
	if resp.Confidence < c.minScore {
		return "", "", 0, false
	}
	return resp.Category, resp.Profile, resp.Confidence, true
}

func (c *LLM) isKnownCategory(category string) bool {
	for _, want := range c.categories {
		if want == category {
			return true
		}
	}
	return false
}

// buildPrompt renders a fixed-shape prompt: field identity, a bounded sample of values, the closed
// taxonomy the model must pick from, and the required JSON response shape. Kept deliberately
// simple/templated rather than provider-specific prompt engineering, since the taxonomy constraint
// (isKnownCategory) — not prompt phrasing — is what keeps a bad response from ever reaching
// label.Store.
func (c *LLM) buildPrompt(objectID, fieldPath string, samples []string) string {
	var b strings.Builder
	b.WriteString("You are classifying a database field for personally identifiable information (PII).\n")
	fmt.Fprintf(&b, "Table/collection: %s\n", objectID)
	fmt.Fprintf(&b, "Field path: %s\n", fieldPath)
	b.WriteString("Sample values:\n")
	for _, v := range samples {
		fmt.Fprintf(&b, "- %s\n", v)
	}
	fmt.Fprintf(&b, "Pick exactly one category from this list, or \"none\" if none apply: %s\n", strings.Join(c.categories, ", "))
	b.WriteString("Respond with a single JSON object: {\"category\": \"...\", \"profile\": \"...\", \"confidence\": 0.0-1.0, \"rationale\": \"...\"}\n")
	return b.String()
}

func (c *LLM) complete(ctx context.Context, prompt string) (completionResponse, bool) {
	var out completionResponse
	body, err := json.Marshal(map[string]any{"prompt": prompt})
	if err != nil {
		return out, true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return out, true
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, true
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, true
	}
	return out, false
}

var _ Classifier = (*LLM)(nil)
