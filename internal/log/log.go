// Package log builds the component-tagged, level-gated *slog.Logger every Skybridge binary and
// library package logs through. SKYBRIDGE_LOG_LEVEL (parsed via ParseLevel) controls verbosity —
// "debug" turns on the extra troubleshooting detail that's silent at the default "info" level.
package log

import (
	"io"
	"log/slog"
	"strings"
)

// ParseLevel maps SKYBRIDGE_LOG_LEVEL's string value to a slog.Level. Unrecognized or empty input
// defaults to slog.LevelInfo — never fails startup over a typo'd level.
func ParseLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New returns a text-handler *slog.Logger tagging every line with component (e.g.
// "skybridge-agent", "skybridge-gateway") so customer-facing log output identifies which binary
// produced it without hardcoding any backend/product name into the message text itself.
func New(w io.Writer, component string, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})).With("component", component)
}
