package gateway

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// ErrRateLimited is returned when a native client exceeds configured new-connection limits.
var ErrRateLimited = errors.New("gateway: client connection rate limit exceeded")

// ConnRateLimiter gates new native-client TCP sessions (per client IP and optionally per org).
type ConnRateLimiter interface {
	Allow(clientIP, orgID string) error
}

// NoopConnRateLimiter allows unlimited connections.
type NoopConnRateLimiter struct{}

// Allow implements ConnRateLimiter.
func (NoopConnRateLimiter) Allow(string, string) error { return nil }

type rateWindow struct {
	start time.Time
	count int
}

type connRateLimiter struct {
	perIPLimit  int
	perOrgLimit int
	window      time.Duration
	now         func() time.Time

	mu         sync.Mutex
	ipWindows  map[string]*rateWindow
	orgWindows map[string]*rateWindow
}

// NewConnRateLimiter returns a per-minute connection limiter, or nil when both limits are zero.
func NewConnRateLimiter(perIPLimit, perOrgLimit int) ConnRateLimiter {
	if perIPLimit <= 0 && perOrgLimit <= 0 {
		return nil
	}
	return &connRateLimiter{
		perIPLimit:  perIPLimit,
		perOrgLimit: perOrgLimit,
		window:      time.Minute,
		now:         time.Now,
		ipWindows:   make(map[string]*rateWindow),
		orgWindows:  make(map[string]*rateWindow),
	}
}

// Allow implements ConnRateLimiter.
func (l *connRateLimiter) Allow(clientIP, orgID string) error {
	if l == nil {
		return nil
	}
	ip := HostFromTCPAddr(clientIP)
	if ip == "" {
		ip = strings.TrimSpace(clientIP)
	}
	if err := l.allowKey(l.ipWindows, ip, l.perIPLimit); err != nil {
		return err
	}
	orgID = strings.TrimSpace(orgID)
	if orgID != "" && l.perOrgLimit > 0 {
		if err := l.allowKey(l.orgWindows, orgID, l.perOrgLimit); err != nil {
			return err
		}
	}
	return nil
}

func (l *connRateLimiter) allowKey(windows map[string]*rateWindow, key string, limit int) error {
	if limit <= 0 || key == "" {
		return nil
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	w := windows[key]
	if w == nil || now.Sub(w.start) >= l.window {
		windows[key] = &rateWindow{start: now, count: 1}
		return nil
	}
	w.count++
	if w.count > limit {
		return ErrRateLimited
	}
	return nil
}
