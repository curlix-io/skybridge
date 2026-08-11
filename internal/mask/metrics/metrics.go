// Package metrics buffers pure-metadata masking-outcome counts (never masked/raw values
// themselves) inside the customer's network and periodically flushes them to the Curlix control
// plane, so Ask Curlix / Administration dashboards can show "how much PII did we mask, of what
// type, on which connection" without the SaaS backend ever seeing a value.
//
// Structurally this mirrors internal/pathlabel/remotestore/remotestore.go: an in-memory pending
// map, a push interval, a bounded pending set (maxPendingBuckets), a Start(ctx) that runs a
// background flush loop, and a graceful flush-on-shutdown when ctx is cancelled.
package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	pushTimeout    = 10 * time.Second
	minPushSeconds = 5

	// maxPendingBuckets bounds the number of distinct (connectionKey, entityType, source) buckets
	// tracked between flushes, mirroring remotestore.go's maxPendingLabels — a sustained backend
	// outage must not let this grow without bound. Once full, any NEW bucket (a
	// connectionKey/entityType/source triple not already tracked) is merged into a generic
	// "OTHER" entity-type bucket for that (connectionKey, source) pair instead of being dropped or
	// causing further unbounded growth — an observation is never silently lost, only its
	// entity-type resolution is coarsened once the cardinality cap is hit.
	maxPendingBuckets = 500

	// unspecifiedEntityType is the entity-type value used for "analyzed" observations, which by
	// design (see RecordAnalyzed's doc comment) do not yet know which entity type applies — entity
	// type is only known once a detector/label lookup actually resolves one, which is exactly the
	// moment RecordMasked (not RecordAnalyzed) is called. Analyzed-only counts are therefore
	// tracked in aggregate per (connectionKey, source) rather than broken out per entity type; the
	// per-entity-type breakdown the dashboard cares about (masked item/byte counts) comes entirely
	// from RecordMasked's buckets, which always carry a real entity type.
	unspecifiedEntityType = "UNSPECIFIED"

	// otherEntityType is the overflow bucket entity type. See maxPendingBuckets.
	otherEntityType = "OTHER"
)

// ConnectionKey builds the "{driver}__{connectionRole}" identifier used as connection_key,
// matching the backend's studio_connection_masking_entry_name format
// (backend/src/curlix/organizations/operator_config.py) so a later rollup query can recover the
// driver with split_part(connection_key, '__', 1). driver is lower-cased to match the backend's
// own normalization; connectionRole is used verbatim (the backend doesn't case-fold it either).
func ConnectionKey(driver, connectionRole string) string {
	return strings.ToLower(strings.TrimSpace(driver)) + "__" + strings.TrimSpace(connectionRole)
}

// Config configures the Recorder. A zero-value URL disables the recorder entirely (Enabled()
// reports false, all record methods become no-ops) — mirrors mask.Remote.Enabled()'s pattern so an
// unconfigured deployment pays no cost and sends no requests.
type Config struct {
	URL          string // POST endpoint, e.g. https://app/api/v1/data-studio/studio/native-access/masking-metrics
	Token        string // bearer token (defaults to the agent's main SKYBRIDGE_TOKEN at the config layer)
	OrgID        string
	PushInterval time.Duration // flush interval; floored at minPushSeconds
}

// bucketKey is the aggregation key: one row per (connectionKey, entityType, source) per flush
// window, matching the backend table's uniqueness constraint (organization_id, connection_key,
// entity_type, detection_source, day) — the backend does the day bucketing server-side (its own
// receive-time UTC date), not this agent.
type bucketKey struct {
	connectionKey string
	entityType    string
	source        string
}

type bucketCounts struct {
	countAnalyzed int64
	countMasked   int64
	bytesMasked   int64
}

// batchEntry mirrors the FastAPI MaskingMetricsBatchItem model
// (POST .../studio/native-access/masking-metrics).
type batchEntry struct {
	ConnectionKey   string `json:"connection_key"`
	EntityType      string `json:"entity_type"`
	DetectionSource string `json:"detection_source"`
	CountAnalyzed   int64  `json:"count_analyzed"`
	CountMasked     int64  `json:"count_masked"`
	BytesMasked     int64  `json:"bytes_masked"`
}

type batchBody struct {
	Entries []batchEntry `json:"entries"`
}

// Recorder buffers masking-outcome counts in memory and flushes them to the control plane on a
// ticker. Zero value is not usable; call New. Safe for concurrent use.
type Recorder struct {
	url    string
	token  string
	orgID  string
	client *http.Client

	pushInterval time.Duration

	mu      sync.Mutex
	pending map[bucketKey]*bucketCounts

	logger *slog.Logger
}

// New builds a Recorder from cfg. When cfg.URL is empty, Enabled() reports false and every record
// method is a safe no-op (no goroutines started, no allocations beyond the zero value).
func New(cfg Config, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	push := cfg.PushInterval
	if push < minPushSeconds*time.Second {
		push = minPushSeconds * time.Second
	}
	return &Recorder{
		url:          strings.TrimSpace(cfg.URL),
		token:        strings.TrimSpace(cfg.Token),
		orgID:        strings.TrimSpace(cfg.OrgID),
		client:       &http.Client{Timeout: pushTimeout},
		pushInterval: push,
		pending:      make(map[bucketKey]*bucketCounts),
		logger:       logger,
	}
}

// Enabled reports whether the recorder is configured to actually push anywhere.
func (r *Recorder) Enabled() bool {
	return r != nil && r.url != ""
}

// RecordAnalyzed records one eligible text value having been passed into a masker's MaskRow,
// regardless of outcome. See unspecifiedEntityType's doc comment for why this does not carry an
// entity type. source is either "recognizer" (Remote/Presidio) or "field_rule" (PathOverlay) — two
// distinct taxonomies that must never be merged into one bucket.
func (r *Recorder) RecordAnalyzed(connectionKey, source string) {
	if !r.Enabled() {
		return
	}
	r.bump(bucketKey{connectionKey: connectionKey, entityType: unspecifiedEntityType, source: source}, func(b *bucketCounts) {
		b.countAnalyzed++
	})
}

// RecordMasked records one value that WAS actually masked/redacted, attributing byteCount bytes to
// entityType under source. entityType is whatever vocabulary source uses verbatim (Presidio's
// EMAIL_ADDRESS vs. Object Field Rules' category names like email_fields) — callers must not
// normalize across the two taxonomies.
func (r *Recorder) RecordMasked(connectionKey, entityType string, byteCount int, source string) {
	if !r.Enabled() {
		return
	}
	et := strings.TrimSpace(entityType)
	if et == "" {
		et = unspecifiedEntityType
	}
	if byteCount < 0 {
		byteCount = 0
	}
	r.bump(bucketKey{connectionKey: connectionKey, entityType: et, source: source}, func(b *bucketCounts) {
		b.countMasked++
		b.bytesMasked += int64(byteCount)
	})
}

// bump applies update to the bucket for key, creating it if absent, and enforces maxPendingBuckets
// by folding overflow into the (connectionKey, source) "OTHER" bucket instead of dropping the
// observation or growing pending without bound.
func (r *Recorder) bump(key bucketKey, update func(*bucketCounts)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.pending[key]
	if !ok {
		if len(r.pending) >= maxPendingBuckets {
			key = bucketKey{connectionKey: key.connectionKey, entityType: otherEntityType, source: key.source}
			b, ok = r.pending[key]
			if !ok {
				// Even the OTHER bucket doesn't exist yet and the map is already at cap — evict an
				// arbitrary existing bucket to make room rather than letting pending grow past
				// maxPendingBuckets. Map iteration order is randomized by Go, so this has no bias
				// toward any particular connection/entity/source.
				for evictKey := range r.pending {
					delete(r.pending, evictKey)
					break
				}
			}
		}
		if !ok {
			b = &bucketCounts{}
			r.pending[key] = b
		}
	}
	update(b)
}

// Start begins the background flush loop and returns immediately. The loop stops when ctx is
// done, flushing one final time so observations made just before shutdown aren't lost (same shape
// as remotestore.Store.Start's push loop).
func (r *Recorder) Start(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	go func() {
		t := time.NewTicker(r.pushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				r.flush(context.Background())
				return
			case <-t.C:
				r.flush(ctx)
			}
		}
	}()
}

// flush drains the current pending buckets and POSTs them as one batch. On failure, the drained
// buckets are merged back into pending (bounded by maxPendingBuckets, same overflow policy as
// bump) so a transient backend outage does not lose observations — mirrors
// remotestore.flushPush/restorePending.
func (r *Recorder) flush(ctx context.Context) {
	drained := r.drain()
	if len(drained) == 0 {
		return
	}
	if err := r.push(ctx, drained); err != nil {
		r.logger.Warn(fmt.Sprintf("masking-metrics push failed: %v (%d buckets retained for next flush)", err, len(drained)))
		r.restore(drained)
	}
}

func (r *Recorder) drain() map[bucketKey]*bucketCounts {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.pending
	r.pending = make(map[bucketKey]*bucketCounts)
	return out
}

func (r *Recorder) restore(drained map[bucketKey]*bucketCounts) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, counts := range drained {
		existing, ok := r.pending[key]
		if !ok {
			if len(r.pending) >= maxPendingBuckets {
				key = bucketKey{connectionKey: key.connectionKey, entityType: otherEntityType, source: key.source}
				existing, ok = r.pending[key]
				if !ok {
					// Same safety net as bump(): even the OTHER bucket doesn't exist yet and pending is
					// already at cap — evict an arbitrary existing bucket rather than let a sustained
					// backend outage grow pending past maxPendingBuckets across repeated failed flushes.
					for evictKey := range r.pending {
						delete(r.pending, evictKey)
						break
					}
				}
			}
		}
		if !ok {
			merged := *counts
			r.pending[key] = &merged
			continue
		}
		existing.countAnalyzed += counts.countAnalyzed
		existing.countMasked += counts.countMasked
		existing.bytesMasked += counts.bytesMasked
	}
}

func (r *Recorder) push(ctx context.Context, buckets map[bucketKey]*bucketCounts) error {
	body := batchBody{Entries: make([]batchEntry, 0, len(buckets))}
	for key, counts := range buckets {
		body.Entries = append(body.Entries, batchEntry{
			ConnectionKey:   key.connectionKey,
			EntityType:      key.entityType,
			DetectionSource: key.source,
			CountAnalyzed:   counts.countAnalyzed,
			CountMasked:     counts.countMasked,
			BytesMasked:     counts.bytesMasked,
		})
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	fctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fctx, http.MethodPost, r.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	if r.orgID != "" {
		req.Header.Set("X-Curlix-Organization-Id", r.orgID)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &httpStatusError{url: r.url, status: resp.StatusCode, body: strings.TrimSpace(string(snippet))}
	}
	return nil
}

type httpStatusError struct {
	url    string
	status int
	body   string
}

func (e *httpStatusError) Error() string {
	return "masking-metrics " + e.url + " -> " + itoa(e.status) + ": " + e.body
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
