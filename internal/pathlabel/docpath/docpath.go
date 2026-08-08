// Package docpath walks map[string]any/[]any document trees and produces
// index-erased, resolved-path leaves (see github.com/curlix-io/pathlabel design
// doc §3.1). Vendored from github.com/curlix-io/pathlabel for use by
// internal/mask's path-scoped overlay.
package docpath

import (
	"sort"
	"strings"
)

// Leaf is a single string value or key encountered while walking a document.
//
// Path is the index-erased resolved path to the leaf (see §3.1): array
// indices are always rendered as "[]", never a literal index, since array
// position has no stable identity across documents in a schemaless collection.
//
// IsKey distinguishes a leaf representing a map key itself (§3.1.1, for
// documents that use PII as a key, e.g. {"user@email.com": {...}}) from an
// ordinary value leaf. For a key leaf, Path is the path of the enclosing map
// (i.e. the key's own parent path, not including the key itself), and Value
// equals Key.
type Leaf struct {
	Path  string
	Key   string
	Value string
	IsKey bool
}

// Walk recurses through doc (expected to be built from map[string]any and
// []any, as produced by encoding/json) and returns every string leaf and
// every map key as a Leaf. Non-string values (numbers, bools, nil) are not
// visited.
//
// Map key iteration order is sorted for deterministic output; it carries no
// meaning about the underlying document.
func Walk(doc any) []Leaf {
	var leaves []Leaf
	walk(doc, "", func(l Leaf) { leaves = append(leaves, l) })
	return leaves
}

func walk(node any, path string, emit func(Leaf)) {
	switch v := node.(type) {
	case map[string]any:
		for _, k := range sortedKeys(v) {
			emit(Leaf{Path: path, Key: k, Value: k, IsKey: true})
			walk(v[k], joinPath(path, k), emit)
		}
	case []any:
		arrPath := path + "[]"
		for _, item := range v {
			walk(item, arrPath, emit)
		}
	case string:
		emit(Leaf{Path: path, Key: lastSegment(path), Value: v})
	}
}

// Replace walks doc and, for every leaf where match returns true, overwrites
// it in place with the string returned by replace: a value leaf's string is
// replaced, a key leaf's map key is renamed (its value is preserved under the
// new key). Replace returns the count of leaves matched (and thus mutated).
// doc must be a mutable map[string]any/[]any tree — Replace panics if doc's
// root is not one of those two shapes.
//
// Because array indices are erased in Path, match is evaluated against every
// leaf independently — there is no way to target "the 3rd element"
// specifically, consistent with §3.1's index-erasure rationale.
func Replace(doc any, match func(Leaf) bool, replace func(Leaf) string) int {
	count := 0
	replaceIn(doc, "", func(l Leaf) (string, bool) {
		if !match(l) {
			return "", false
		}
		count++
		return replace(l), true
	})
	return count
}

// replaceIn mutates node in place (maps/slices are reference types, so
// mutations to v below are visible to the caller without needing node
// returned back up the call stack).
func replaceIn(node any, path string, decide func(Leaf) (string, bool)) {
	switch v := node.(type) {
	case map[string]any:
		for _, k := range sortedKeys(v) {
			if newKey, ok := decide(Leaf{Path: path, Key: k, Value: k, IsKey: true}); ok && newKey != k {
				v[newKey] = v[k]
				delete(v, k)
				k = newKey
			}
			child := v[k]
			if s, isStr := child.(string); isStr {
				if newVal, ok := decide(Leaf{Path: path, Key: lastSegment(joinPath(path, k)), Value: s}); ok {
					v[k] = newVal
					continue
				}
			}
			replaceIn(child, joinPath(path, k), decide)
		}
	case []any:
		arrPath := path + "[]"
		for i, item := range v {
			if s, isStr := item.(string); isStr {
				if newVal, ok := decide(Leaf{Path: arrPath, Key: lastSegment(arrPath), Value: s}); ok {
					v[i] = newVal
					continue
				}
			}
			replaceIn(item, arrPath, decide)
		}
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func lastSegment(path string) string {
	if path == "" {
		return ""
	}
	seg := path
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		seg = path[idx+1:]
	}
	return strings.TrimSuffix(seg, "[]")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
