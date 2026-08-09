package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// recognizersFile mirrors Presidio's own recognizer config shape (the "recognizer_registry:
// recognizers:" document Presidio's RecognizerRegistry.from_yaml loads), so an admin can lift
// entries straight from Presidio's docs rather than learning a Curlix-specific format:
//
//	recognizers:
//	  - name: AcmeAccountNumberRecognizer
//	    supported_language: en
//	    patterns:
//	      - name: acme_account_number
//	        regex: "ACME-\\d{9}"
//	        score: 0.8
//	    context: ["account", "acme"]
//	    supported_entity: ACME_ACCOUNT_NUMBER
type recognizersFile struct {
	Recognizers []map[string]any `yaml:"recognizers"`
}

// LoadRecognizers resolves the configured custom recognizers into the "ad_hoc_recognizers" array
// Presidio's /analyze endpoint accepts verbatim in the request body. This is Presidio's supported
// way to add custom recognizers without rebuilding the analyzer image.
//
// inlineYAML (SKYBRIDGE_MASK_RECOGNIZERS_YAML) takes priority when set — it's populated by ECS
// injecting an SSM Parameter Store value straight into the container env via the task
// definition's Secrets:ValueFrom (the same mechanism already used for SKYBRIDGE_ENROLLMENT_TOKEN
// in curlix-edge.yaml), so no AWS SDK call or extra IAM permission is needed inside this binary —
// updating the SSM parameter and restarting the task rotates the recognizers.
//
// filePath (SKYBRIDGE_MASK_RECOGNIZERS_FILE) is the local-disk fallback used by docker-compose /
// local dev, where mounting a file is simpler than wiring SSM.
//
// Returns nil, nil when neither is set (custom recognizers are off by default).
func LoadRecognizers(inlineYAML, filePath string) ([]any, error) {
	if inlineYAML != "" {
		return parseRecognizersYAML([]byte(inlineYAML), "SKYBRIDGE_MASK_RECOGNIZERS_YAML")
	}
	if filePath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("config: reading recognizers file %q: %w", filePath, err)
	}
	return parseRecognizersYAML(raw, filePath)
}

func parseRecognizersYAML(raw []byte, source string) ([]any, error) {
	var doc recognizersFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("config: parsing recognizers YAML (%s): %w", source, err)
	}
	out := make([]any, len(doc.Recognizers))
	for i, r := range doc.Recognizers {
		out[i] = r
	}
	return out, nil
}
