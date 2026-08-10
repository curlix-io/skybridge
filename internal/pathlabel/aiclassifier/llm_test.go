package aiclassifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewLLM_PanicsOnMissingEndpoint(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when Endpoint is empty")
		}
	}()
	NewLLM(LLMConfig{Categories: []string{"email_fields"}})
}

func TestNewLLM_PanicsOnEmptyTaxonomy(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when Categories is empty")
		}
	}()
	NewLLM(LLMConfig{Endpoint: "http://example"})
}

func TestLLMClassify_ReturnsProposalOnKnownCategory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(completionResponse{
			Category: "email_fields", Profile: "full_redact", Confidence: 0.87, Rationale: "looks like an email",
		})
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields", "ssn_fields"}})
	category, profile, confidence, ok := c.Classify(context.Background(), "org:pg:db:users", "email", []string{"a@b.com"})
	if !ok {
		t.Fatal("expected ok=true for a known-taxonomy response")
	}
	if category != "email_fields" || profile != "full_redact" || confidence != 0.87 {
		t.Fatalf("unexpected result: category=%q profile=%q confidence=%v", category, profile, confidence)
	}
}

func TestLLMClassify_RejectsUnknownCategory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(completionResponse{Category: "not_in_taxonomy", Confidence: 0.99})
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields"}})
	_, _, _, ok := c.Classify(context.Background(), "org", "field", []string{"v"})
	if ok {
		t.Fatal("expected ok=false when the model returns a category outside the configured taxonomy")
	}
}

func TestLLMClassify_RejectsBelowMinConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(completionResponse{Category: "email_fields", Confidence: 0.2})
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields"}, MinConfidence: 0.5})
	_, _, _, ok := c.Classify(context.Background(), "org", "field", []string{"v"})
	if ok {
		t.Fatal("expected ok=false when confidence is below MinConfidence")
	}
}

func TestLLMClassify_FailsClosedOnTransportError(t *testing.T) {
	c := NewLLM(LLMConfig{Endpoint: "http://127.0.0.1:0", Categories: []string{"email_fields"}})
	_, _, _, ok := c.Classify(context.Background(), "org", "field", []string{"v"})
	if ok {
		t.Fatal("expected ok=false on a transport error, never a proposal")
	}
}

func TestLLMClassify_FailsClosedOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields"}})
	_, _, _, ok := c.Classify(context.Background(), "org", "field", []string{"v"})
	if ok {
		t.Fatal("expected ok=false on a non-200 response")
	}
}

func TestLLMClassify_FailsClosedOnMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields"}})
	_, _, _, ok := c.Classify(context.Background(), "org", "field", []string{"v"})
	if ok {
		t.Fatal("expected ok=false on a malformed JSON response body")
	}
}

func TestLLMClassify_RejectsBelowMinSamples(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_ = json.NewEncoder(w).Encode(completionResponse{Category: "email_fields", Confidence: 0.9})
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields"}, MinSamples: 3})
	_, _, _, ok := c.Classify(context.Background(), "org", "field", []string{"v1", "v2"})
	if ok {
		t.Fatal("expected ok=false when fewer than MinSamples are supplied")
	}
	if called {
		t.Fatal("expected no HTTP call when the sample count is below MinSamples")
	}
}

func TestLLMClassify_SendsBearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(completionResponse{Category: "email_fields", Confidence: 0.9})
	}))
	defer srv.Close()

	c := NewLLM(LLMConfig{Endpoint: srv.URL, Categories: []string{"email_fields"}, APIKey: "secret-token"})
	c.Classify(context.Background(), "org", "field", []string{"v"})
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("expected Authorization header to carry the API key, got %q", gotAuth)
	}
}
