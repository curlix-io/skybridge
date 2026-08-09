//go:build querystudio

package dbquery

import (
	"errors"
	"regexp"
	"strings"
)

func enforceReadOnlySQL(q string) error {
	if isWriteSQL(q) {
		return errors.New("write statements blocked on execution agent")
	}
	return nil
}

// writeKeywordRe matches SQL DML/DDL keywords likely to mutate data or schema, as whole words.
// isWriteSQL runs this against the statement with comments and string literals stripped, and scans
// the whole statement rather than only its prefix — a leading `-- comment` or a data-modifying CTE
// (`WITH d AS (DELETE FROM t RETURNING id) SELECT * FROM d`) would otherwise start with a harmless
// keyword and slip past a prefix-only check.
var writeKeywordRe = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|MERGE)\b`)

func isWriteSQL(q string) bool {
	return writeKeywordRe.MatchString(stripSQLNoise(q))
}

// stripSQLNoise removes `--` line comments, `/* */` block comments, and single-quoted string
// literal bodies (so keyword matching isn't fooled by a comment hiding a keyword, nor by literal
// text like 'please DELETE this ticket' inside a read-only SELECT).
func stripSQLNoise(q string) string {
	var b strings.Builder
	n := len(q)
	for i := 0; i < n; {
		switch c := q[i]; {
		case c == '\'':
			b.WriteByte(' ')
			i++
			for i < n {
				if q[i] == '\'' {
					if i+1 < n && q[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case c == '-' && i+1 < n && q[i+1] == '-':
			for i < n && q[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && q[i+1] == '*':
			i += 2
			for i+1 < n && !(q[i] == '*' && q[i+1] == '/') {
				i++
			}
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// mongoWriteSubstrings are lowercase substrings of a Mongo shell statement that indicate a write:
// CRUD method calls (dot-prefixed to avoid matching field names like "updatedAt"), plus the
// aggregation pipeline stages ($out/$merge) that write documents without calling any CRUD method at
// all — a $merge/$out substring match is safe against false positives since "$" is a reserved
// operator prefix in Mongo query/pipeline syntax, never a plain field or value.
var mongoWriteSubstrings = []string{
	".insert", ".update", ".delete", ".remove", ".replace", ".save", ".drop",
	".createindex", ".createcollection", ".renamecollection", ".bulkwrite",
	".findoneandupdate", ".findoneandreplace", ".findoneanddelete",
	"$out", "$merge",
}

func enforceReadOnlyMongo(stmt string) error {
	low := strings.ToLower(strings.TrimSpace(stmt))
	for _, bad := range mongoWriteSubstrings {
		if strings.Contains(low, bad) {
			return errors.New("mongo write operations blocked on execution agent")
		}
	}
	return nil
}
