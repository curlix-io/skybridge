// Package mongosampler implements aiclassifier.Sampler over the mongo-driver client for MongoDB —
// the read-only, off-the-hot-path document sampling docs/AI_PATH_LABELLING_DESIGN.md §5.2 describes,
// the Mongo counterpart to internal/pathlabel/sqlsampler's SQL implementation. This is a sampling
// connection, not a wire-proxy or client-session connection: it exists purely to feed the periodic
// classification scan (cmd/skybridge-labeller) and never touches live query traffic. Callers are
// expected to use a dedicated, read-only credential, the same posture sqlsampler's callers use.
//
// Unlike SQL, a Mongo collection has no fixed schema to enumerate — ListColumns (kept as the same
// method name as sqlsampler's, so both satisfy the same caller-side interface in internal/labeller)
// discovers fields by sampling a bounded number of documents and walking them with
// internal/pathlabel/docpath, the same nested-path convention internal/edge/dbquery's maskDocuments
// already uses for live Mongo traffic — so a label this job proposes for "profile.email" lines up
// with the FieldPath PathOverlay looks up for the same nested field on the wire.
package mongosampler

import (
	"context"
	"sort"
	"strings"

	"github.com/curlix-io/skybridge/internal/pathlabel/docpath"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// schemaSampleSize bounds how many documents ListColumns inspects to discover field paths — a
// schema-discovery scan, not a per-field value sample (see maxSamples on Sample), so it only needs
// enough documents to see the collection's field shape, not a statistically large sample.
const schemaSampleSize = 20

// Sampler implements aiclassifier.Sampler by querying a bounded set of documents per
// (objectID, fieldPath). Zero value is not usable; call New.
type Sampler struct {
	client *mongo.Client
}

// New returns a Sampler over client. client is expected to be a dedicated, read-only sampling
// connection (docs/AI_PATH_LABELLING_DESIGN.md §5.2), never the same client a live wire-proxy
// session or native client uses.
func New(client *mongo.Client) *Sampler {
	return &Sampler{client: client}
}

// objectIDParts extracts database and collection from an ObjectID shaped
// "{org}:mongo:{database}:{collection}" (internal/edge/dbquery's objectID convention, also used by
// internal/pathlabel/remotestore) — the last two colon-separated segments.
func objectIDParts(objectID string) (database, collection string, ok bool) {
	parts := strings.Split(objectID, ":")
	if len(parts) < 4 {
		return "", "", false
	}
	return parts[len(parts)-2], parts[len(parts)-1], true
}

// mongoQueryPath converts docpath's index-erased dot path ("tags[].name", "tags[]") into the plain
// dot-notation Mongo itself expects for a filter/projection path ("tags.name", "tags") — Mongo
// already matches across array elements on a dotted path implicitly, so the "[]" marker (meaningful
// only to docpath's own leaf identity, never to Mongo) is simply dropped rather than translated to
// anything Mongo-specific.
func mongoQueryPath(fieldPath string) string {
	return strings.ReplaceAll(fieldPath, "[]", "")
}

// Sample implements aiclassifier.Sampler: finds up to maxSamples documents where fieldPath exists
// and is non-null, and returns every matching string leaf's value at that exact resolved path.
// ok=false on any error (bad ObjectID shape, query failure) or an empty result — a sampling failure
// for one field must never abort the caller's scan over the rest of an object's fields
// (aiclassifier.Sampler's own doc comment).
func (s *Sampler) Sample(ctx context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool) {
	database, collection, ok := objectIDParts(objectID)
	if !ok || fieldPath == "" || maxSamples <= 0 {
		return nil, false
	}
	qp := mongoQueryPath(fieldPath)
	coll := s.client.Database(database).Collection(collection)
	filter := bson.M{qp: bson.M{"$exists": true, "$ne": nil}}
	findOpts := options.Find().SetProjection(bson.M{qp: 1, "_id": 0}).SetLimit(int64(maxSamples))
	cursor, err := coll.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, false
	}
	defer cursor.Close(ctx)

	var out []string
	for len(out) < maxSamples && cursor.Next(ctx) {
		var doc map[string]any
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		for _, leaf := range docpath.Walk(normalizeDoc(doc)) {
			if leaf.IsKey || leaf.Path != fieldPath {
				continue
			}
			out = append(out, leaf.Value)
			if len(out) >= maxSamples {
				break
			}
		}
	}
	if err := cursor.Err(); err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// ListColumns discovers collection's observed field paths by sampling up to schemaSampleSize
// documents and walking them via docpath.Walk — there is no real schema catalog to query, so this
// is a best-effort discovery pass, not an authoritative field list; a field absent from every
// sampled document simply won't be scanned this cycle. database selects which logical database
// collection lives in (a Mongo client, unlike a database/sql.DB opened against one DSN, isn't
// scoped to a single database). schema-shaped signature (schema, table) is kept identical to
// sqlsampler.Sampler.ListColumns so callers can treat both behind one interface.
func (s *Sampler) ListColumns(ctx context.Context, database, collection string) ([]string, error) {
	coll := s.client.Database(database).Collection(collection)
	findOpts := options.Find().SetLimit(schemaSampleSize)
	cursor, err := coll.Find(ctx, bson.M{}, findOpts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	seen := make(map[string]bool)
	var out []string
	for cursor.Next(ctx) {
		var doc map[string]any
		if err := cursor.Decode(&doc); err != nil {
			return nil, err
		}
		for _, leaf := range docpath.Walk(normalizeDoc(doc)) {
			if leaf.IsKey || seen[leaf.Path] {
				continue
			}
			seen[leaf.Path] = true
			out = append(out, leaf.Path)
		}
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// ListTables returns database's collection names via the driver's own catalog command
// (ListCollectionNames) — unlike ListColumns' field discovery, this is an authoritative list, not a
// best-effort sample, since Mongo does track collection names in a real catalog even though it
// tracks nothing about their field shape. Used by the scan job to discover which collections to
// scan when the caller doesn't supply an explicit list.
func (s *Sampler) ListTables(ctx context.Context, database string) ([]string, error) {
	names, err := s.client.Database(database).ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// normalizeDoc converts the driver's decoded types (bson.M/bson.A, named types over
// map[string]any/[]any) into plain map[string]any/[]any recursively, so docpath.Walk's type switch
// (which matches only the plain, unnamed types) sees every nested level — mirrors
// internal/edge/dbquery's normalizeBSONDoc, duplicated here rather than imported since that package
// lives behind the querystudio build tag and this one doesn't.
func normalizeDoc(doc map[string]any) map[string]any {
	return normalizeVal(doc).(map[string]any)
}

func normalizeVal(v any) any {
	switch x := v.(type) {
	case bson.M:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeVal(vv)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeVal(vv)
		}
		return out
	case bson.A:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = normalizeVal(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = normalizeVal(vv)
		}
		return out
	default:
		return v
	}
}

var _ interface {
	Sample(ctx context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool)
} = (*Sampler)(nil)
