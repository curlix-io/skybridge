// Package remotestore implements label.Store by syncing with the Curlix control plane over plain
// HTTP, mirroring internal/agent/overlay_source.go's poll pattern: confirmed (manual/platform)
// labels are pulled into a local read cache on an interval, and locally-observed proposed labels
// are batched and flushed to the control plane on a separate interval. Lookup/ListBySource never
// block on a live HTTP call (label.Store's own contract: Lookup runs on every leaf at redact time),
// and Put never blocks on one either — it only appends to an in-memory pending batch.
package remotestore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

const (
	fetchTimeout   = 10 * time.Second
	minPollSeconds = 15
	minPushSeconds = 5

	// maxPendingLabels bounds the in-memory push queue so a sustained backend outage cannot grow
	// this without limit; once full, the lowest-confidence pending label is dropped to make room
	// for the newest observation (CLAUDE.md's no-unbounded-growth rule applies edge-side too).
	maxPendingLabels = 500
)

// pullResponse mirrors the FastAPI SkybridgePathLabelsOut model (GET .../pii-path-labels).
type pullResponse struct {
	OrganizationID string      `json:"organization_id"`
	Labels         []labelWire `json:"labels"`
	Count          int         `json:"count"`
	GeneratedUnix  int64       `json:"generated_unix"`
}

type labelWire struct {
	Driver       string `json:"driver"`
	DatabaseName string `json:"database_name"`
	ObjectName   string `json:"object_name"`
	FieldPath    string `json:"field_path"`
	MatchMode    string `json:"match_mode"`
	Category     string `json:"category"`
	Profile      string `json:"profile"`
	Source       string `json:"source"`
}

// proposeItem mirrors the FastAPI PathLabelProposeItem model (POST .../pii-path-labels/propose).
type proposeItem struct {
	FieldPath      string    `json:"field_path"`
	MatchMode      string    `json:"match_mode"`
	Category       string    `json:"category,omitempty"`
	Confidence     float64   `json:"confidence"`
	SampleCount    int       `json:"sample_count"`
	LastObservedAt time.Time `json:"last_observed_at,omitempty"`
}

type proposeBody struct {
	Driver       string        `json:"driver"`
	DatabaseName string        `json:"database_name"`
	ObjectName   string        `json:"object_name"`
	Labels       []proposeItem `json:"labels"`
}

// Store implements label.Store by syncing with the control plane. Zero value is not usable; call
// New. Safe for concurrent use per label.Store's contract.
type Store struct {
	pullURL string
	token   string
	orgID   string
	client  *http.Client

	pollInterval time.Duration
	pushInterval time.Duration

	mu      sync.RWMutex
	cache   map[cacheKey]label.Label // confirmed labels only (manual/platform)
	pending map[pendingKey]label.Label

	logger *slog.Logger
}

type cacheKey struct {
	objectID  string
	fieldPath string
}

type pendingKey struct {
	objectID  string
	fieldPath string
}

func objectParts(objectID string) (driver, database, object string, ok bool) {
	// dbquery.objectID builds "{org}:{driver}:{db}:{object}" — see
	// internal/edge/dbquery/executor.go's objectID helper. Split on ':' and take the last three
	// parts so an org id containing ':' (unlikely, but not enforced) doesn't break the split.
	parts := strings.Split(objectID, ":")
	if len(parts) < 4 {
		return "", "", "", false
	}
	n := len(parts)
	return parts[n-3], parts[n-2], parts[n-1], true
}

// New returns a Store configured from cfg. cfg.PathLabelURL must be set; callers should check that
// before constructing (mirrors newOverlaySource's caller-checks-first convention).
func New(cfg config.Agent, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	poll := time.Duration(cfg.PathLabelPollSeconds) * time.Second
	if poll < minPollSeconds*time.Second {
		poll = minPollSeconds * time.Second
	}
	push := time.Duration(cfg.PathLabelPushSeconds) * time.Second
	if push < minPushSeconds*time.Second {
		push = minPushSeconds * time.Second
	}
	return &Store{
		pullURL:      strings.TrimSpace(cfg.PathLabelURL),
		token:        strings.TrimSpace(cfg.PathLabelToken),
		orgID:        strings.TrimSpace(cfg.OrgID),
		client:       &http.Client{Timeout: fetchTimeout},
		pollInterval: poll,
		pushInterval: push,
		cache:        make(map[cacheKey]label.Label),
		pending:      make(map[pendingKey]label.Label),
		logger:       logger,
	}
}

// Lookup implements label.Store, served entirely from the local confirmed-label cache.
func (s *Store) Lookup(_ context.Context, objectID, fieldPath string) (label.Label, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.cache[cacheKey{objectID: objectID, fieldPath: fieldPath}]
	return l, ok, nil
}

// ListBySource implements label.Store. Only SourceManual/SourcePlatform are ever cached locally
// (the pull endpoint only returns confirmed labels), so a query for any other source returns empty.
func (s *Store) ListBySource(_ context.Context, objectID string, source label.Source) ([]label.Label, error) {
	if source != label.SourceManual && source != label.SourcePlatform {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []label.Label
	for _, l := range s.cache {
		if l.ObjectID == objectID && l.Source == source {
			out = append(out, l)
		}
	}
	return out, nil
}

// Put implements label.Store. It never makes a network call itself — it merges l into the pending
// push batch (same merge semantics as label.MemStore.mergeProposed) and lets the background
// flusher started by Start deliver it. Only SourceProposed labels are queued; other sources aren't
// expected from local detectors and are dropped with a log line rather than silently ignored.
func (s *Store) Put(_ context.Context, l label.Label) error {
	if l.ObjectID == "" || l.FieldPath == "" {
		return fmt.Errorf("remotestore: ObjectID and FieldPath are required")
	}
	if l.Source != label.SourceProposed {
		s.logger.Warn(fmt.Sprintf("Put ignoring non-proposed label source=%q object=%q path=%q", l.Source, l.ObjectID, l.FieldPath))
		return nil
	}
	if l.MatchMode == "" {
		l.MatchMode = label.MatchPath
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	k := pendingKey{objectID: l.ObjectID, fieldPath: l.FieldPath}
	if existing, ok := s.pending[k]; ok {
		l = mergeProposed(existing, l)
	} else if len(s.pending) >= maxPendingLabels {
		s.evictLowestConfidenceLocked()
	}
	s.pending[k] = l
	return nil
}

func mergeProposed(existing, incoming label.Label) label.Label {
	merged := incoming
	merged.SampleCount = existing.SampleCount + incoming.SampleCount
	if existing.Confidence > merged.Confidence {
		merged.Confidence = existing.Confidence
	}
	if existing.LastObservedAt.After(merged.LastObservedAt) {
		merged.LastObservedAt = existing.LastObservedAt
	}
	return merged
}

// evictLowestConfidenceLocked drops the pending label with the lowest confidence to make room for
// a new observation. Caller must hold s.mu.
func (s *Store) evictLowestConfidenceLocked() {
	var worstKey pendingKey
	var worst label.Label
	first := true
	for k, l := range s.pending {
		if first || l.Confidence < worst.Confidence {
			worstKey, worst = k, l
			first = false
		}
	}
	if !first {
		delete(s.pending, worstKey)
	}
}

// Start begins the pull poll loop and push flush loop in the background and returns immediately.
// Both loops stop when ctx is done; call Stop first (or let ctx cancellation flush a final batch)
// during shutdown so observations made just before exit aren't silently lost.
func (s *Store) Start(ctx context.Context) {
	s.refreshPull(ctx)
	go func() {
		defer s.recoverBackground("pii-path-labels pull sync")
		t := time.NewTicker(s.pollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refreshPull(ctx)
			}
		}
	}()
	go func() {
		defer s.recoverBackground("pii-path-labels push sync")
		t := time.NewTicker(s.pushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				s.flushPush(context.Background())
				return
			case <-t.C:
				s.flushPush(ctx)
			}
		}
	}()
}

// recoverBackground stops a panic from propagating out of Start's background pull/push loops — an
// unhandled parsing edge case on a malformed/adversarial control-plane response must only stop
// this one sync loop, not crash the whole agent process and every live database session sharing
// it. Mirrors internal/agent's recoverBackground; kept local since this is a different package.
func (s *Store) recoverBackground(name string) {
	r := recover()
	if r == nil {
		return
	}
	s.logger.Error(fmt.Sprintf("recovered from panic in %s: %v\n%s", name, r, debug.Stack()))
}

func (s *Store) refreshPull(ctx context.Context) {
	// The pull endpoint is object-scoped (driver/database_name/object_name query params), but this
	// Store is process-wide — refresh every object currently represented in the cache or pending
	// batch so newly-confirmed labels for any previously-seen object get picked up. An object with
	// no prior activity is only added to the cache once dbquery observes it (via Put or a Lookup
	// miss that later becomes a confirmed label after an admin reviews it) — this mirrors
	// overlay_source.go's best-effort "seed on first use" posture rather than requiring a static
	// object list up front.
	objects := s.knownObjectIDs()
	for _, objectID := range objects {
		driver, db, obj, ok := objectParts(objectID)
		if !ok {
			continue
		}
		labels, err := s.pull(ctx, driver, db, obj)
		if err != nil {
			s.logger.Warn(fmt.Sprintf("pull failed object=%q: %v", objectID, err))
			continue
		}
		s.replaceCacheForObject(objectID, labels)
	}
}

func (s *Store) knownObjectIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	for k := range s.cache {
		seen[k.objectID] = struct{}{}
	}
	for k := range s.pending {
		seen[k.objectID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// SeedObject ensures objectID is tracked by the pull poller even before any label has been cached
// or proposed for it — dbquery call sites should call this once per object at query time so the
// very first pull for a never-before-seen object still happens (otherwise refreshPull only ever
// sees objects it already has something for, per knownObjectIDs above).
func (s *Store) SeedObject(objectID string) {
	if objectID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := cacheKey{objectID: objectID, fieldPath: "\x00seed"}
	if _, ok := s.cache[k]; !ok {
		s.cache[k] = label.Label{} // placeholder entry; never matches a real Lookup (fieldPath sentinel)
	}
}

func (s *Store) pull(ctx context.Context, driver, database, object string) ([]label.Label, error) {
	fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fctx, http.MethodGet, s.pullURL, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("driver", driver)
	q.Set("database_name", database)
	q.Set("object_name", object)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if s.orgID != "" {
		req.Header.Set("X-Curlix-Organization-Id", s.orgID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("pii-path-labels %s -> %d: %s", s.pullURL, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var out pullResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("pii-path-labels decode: %w", err)
	}
	objectID := fmt.Sprintf("%s:%s:%s:%s", s.orgID, driver, database, object)
	labels := make([]label.Label, 0, len(out.Labels))
	for _, w := range out.Labels {
		src := label.Source(w.Source)
		if src != label.SourceManual && src != label.SourcePlatform {
			continue
		}
		mode := label.MatchMode(w.MatchMode)
		if mode == "" {
			mode = label.MatchPath
		}
		labels = append(labels, label.Label{
			ObjectID:  objectID,
			FieldPath: w.FieldPath,
			MatchMode: mode,
			Category:  w.Category,
			Profile:   w.Profile,
			Source:    src,
		})
	}
	return labels, nil
}

func (s *Store) replaceCacheForObject(objectID string, labels []label.Label) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.cache {
		if k.objectID == objectID {
			delete(s.cache, k)
		}
	}
	for _, l := range labels {
		s.cache[cacheKey{objectID: l.ObjectID, fieldPath: l.FieldPath}] = l
	}
	s.logger.Debug(fmt.Sprintf("pii-path-labels synced object=%q (%d confirmed labels)", objectID, len(labels)))
}

// flushPush POSTs the current pending batch, grouped by object, to the control plane. On failure
// the batch for that object is left in place for the next tick (bounded by maxPendingLabels).
func (s *Store) flushPush(ctx context.Context) {
	batches := s.drainPendingByObject()
	for objectID, items := range batches {
		driver, db, obj, ok := objectParts(objectID)
		if !ok {
			continue
		}
		if err := s.push(ctx, driver, db, obj, items); err != nil {
			s.logger.Warn(fmt.Sprintf("push failed object=%q: %v (%d labels retained for next flush)", objectID, err, len(items)))
			s.restorePending(objectID, items)
			continue
		}
	}
}

func (s *Store) drainPendingByObject() map[string][]label.Label {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]label.Label)
	for k, l := range s.pending {
		out[k.objectID] = append(out[k.objectID], l)
	}
	s.pending = make(map[pendingKey]label.Label)
	return out
}

func (s *Store) restorePending(objectID string, items []label.Label) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range items {
		k := pendingKey{objectID: l.ObjectID, fieldPath: l.FieldPath}
		if existing, ok := s.pending[k]; ok {
			l = mergeProposed(existing, l)
		} else if len(s.pending) >= maxPendingLabels {
			s.evictLowestConfidenceLocked()
		}
		s.pending[k] = l
	}
}

func (s *Store) push(ctx context.Context, driver, database, object string, items []label.Label) error {
	body := proposeBody{
		Driver:       driver,
		DatabaseName: database,
		ObjectName:   object,
	}
	for _, l := range items {
		body.Labels = append(body.Labels, proposeItem{
			FieldPath:      l.FieldPath,
			MatchMode:      string(l.MatchMode),
			Category:       l.Category,
			Confidence:     l.Confidence,
			SampleCount:    l.SampleCount,
			LastObservedAt: l.LastObservedAt,
		})
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	url := strings.TrimRight(s.pullURL, "/") + "/propose"
	req, err := http.NewRequestWithContext(fctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if s.orgID != "" {
		req.Header.Set("X-Curlix-Organization-Id", s.orgID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pii-path-labels/propose %s -> %d: %s", url, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

var _ label.Store = (*Store)(nil)
