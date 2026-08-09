package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRecognizersNoSourceReturnsNil(t *testing.T) {
	recognizers, err := LoadRecognizers("", "")
	if err != nil {
		t.Fatal(err)
	}
	if recognizers != nil {
		t.Fatalf("expected nil recognizers with no source, got %v", recognizers)
	}
}

const twoRecognizersYAML = `
recognizers:
  - name: AcmeAccountNumberRecognizer
    supported_language: en
    patterns:
      - name: acme_account_number
        regex: "ACME-\\d{9}"
        score: 0.8
    context: ["account", "acme"]
    supported_entity: ACME_ACCOUNT_NUMBER
  - name: AcmeTicketIDRecognizer
    supported_entity: ACME_TICKET_ID
`

func assertTwoRecognizers(t *testing.T, recognizers []any) {
	t.Helper()
	if len(recognizers) != 2 {
		t.Fatalf("expected 2 recognizers, got %d: %v", len(recognizers), recognizers)
	}
	first, ok := recognizers[0].(map[string]any)
	if !ok || first["supported_entity"] != "ACME_ACCOUNT_NUMBER" {
		t.Fatalf("expected first recognizer to carry supported_entity, got %v", recognizers[0])
	}
	patterns, ok := first["patterns"].([]any)
	if !ok || len(patterns) != 1 {
		t.Fatalf("expected first recognizer to carry one pattern, got %v", first["patterns"])
	}
}

func TestLoadRecognizersParsesInlineYAML(t *testing.T) {
	recognizers, err := LoadRecognizers(twoRecognizersYAML, "")
	if err != nil {
		t.Fatal(err)
	}
	assertTwoRecognizers(t, recognizers)
}

func TestLoadRecognizersParsesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recognizers.yaml")
	if err := os.WriteFile(path, []byte(twoRecognizersYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	recognizers, err := LoadRecognizers("", path)
	if err != nil {
		t.Fatal(err)
	}
	assertTwoRecognizers(t, recognizers)
}

func TestLoadRecognizersInlineYAMLTakesPriorityOverFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recognizers.yaml")
	if err := os.WriteFile(path, []byte("recognizers:\n  - name: FileOnlyRecognizer\n    supported_entity: FILE_ONLY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recognizers, err := LoadRecognizers(twoRecognizersYAML, path)
	if err != nil {
		t.Fatal(err)
	}
	assertTwoRecognizers(t, recognizers)
}

func TestLoadRecognizersMissingFileErrors(t *testing.T) {
	if _, err := LoadRecognizers("", filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadRecognizersInvalidInlineYAMLErrors(t *testing.T) {
	if _, err := LoadRecognizers("recognizers: [not, closed", ""); err == nil {
		t.Fatal("expected error for invalid inline yaml")
	}
}

func TestLoadRecognizersInvalidFileYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recognizers.yaml")
	if err := os.WriteFile(path, []byte("recognizers: [not, closed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecognizers("", path); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}
