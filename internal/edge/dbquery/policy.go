//go:build querystudio

package dbquery

import (
	"errors"
	"strings"
)

func enforceReadOnlySQL(q string) error {
	if isWriteSQL(q) {
		return errors.New("write statements blocked on execution agent")
	}
	return nil
}

func isWriteSQL(q string) bool {
	up := strings.ToUpper(strings.TrimSpace(q))
	for _, prefix := range []string{"INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "CREATE ", "TRUNCATE ", "GRANT ", "REVOKE "} {
		if strings.HasPrefix(up, prefix) {
			return true
		}
	}
	return false
}

func enforceReadOnlyMongo(stmt string) error {
	low := strings.ToLower(strings.TrimSpace(stmt))
	for _, bad := range []string{
		".insert", ".update", ".delete", ".remove", ".drop", ".createindex", ".createcollection",
	} {
		if strings.Contains(low, bad) {
			return errors.New("mongo write operations blocked on execution agent")
		}
	}
	return nil
}
