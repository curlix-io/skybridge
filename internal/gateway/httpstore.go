package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPStore reports native-session lifecycle to an external control plane over HTTP. The control
// plane remains the single writer of the shared session store. Pure net/http so the module stays
// offline-buildable. The base path is configurable so the gateway is not tied to any one backend.
//
// Contract (basePath defaults to /api/v1/data-studio/studio/native-sessions):
//
//	POST {baseURL}{basePath}
//	     body  SessionRecord (json) -> 201 {"id": "<session id>"}
//	POST {baseURL}{basePath}/{id}/close
//	     body  SessionResult (json) -> 200
//
// Authorization: Bearer <token> on both calls.
type HTTPStore struct {
	baseURL  string
	basePath string
	token    string
	client   *http.Client
}

// DefaultSessionPath is used when NewHTTPStore is given an empty basePath.
const DefaultSessionPath = "/api/v1/data-studio/studio/native-sessions"

// NewHTTPStore builds a reporter. baseURL is the control-plane origin; basePath is the session
// lifecycle route (empty uses DefaultSessionPath).
func NewHTTPStore(baseURL, basePath, token string) *HTTPStore {
	bp := strings.TrimRight(strings.TrimSpace(basePath), "/")
	if bp == "" {
		bp = DefaultSessionPath
	}
	return &HTTPStore{
		baseURL:  strings.TrimRight(baseURL, "/"),
		basePath: bp,
		token:    token,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// SessionStarted implements Store.
func (h *HTTPStore) SessionStarted(ctx context.Context, rec SessionRecord) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := h.post(ctx, h.basePath, rec, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// SessionEnded implements Store.
func (h *HTTPStore) SessionEnded(ctx context.Context, sessionID string, res SessionResult) error {
	if strings.TrimSpace(sessionID) == "" {
		return nil
	}
	return h.post(ctx, h.basePath+"/"+sessionID+"/close", res, nil)
}

func (h *HTTPStore) post(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("control plane %s -> %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
