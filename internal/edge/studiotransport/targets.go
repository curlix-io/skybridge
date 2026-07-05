package studiotransport

import "github.com/curlix-io/skybridge/internal/edge/dbquery"

// Target declares a database binding the edge can execute Query Studio assignments for.
type Target = dbquery.Target

// ParseTargets decodes SKYBRIDGE_STUDIO_TARGETS JSON.
func ParseTargets(raw string) []Target {
	return dbquery.ParseTargets(raw)
}
