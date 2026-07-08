package gateway

import (
	"testing"
	"time"
)

func TestConnRateLimiterPerIP(t *testing.T) {
	lim := NewConnRateLimiter(2, 0).(*connRateLimiter)
	lim.now = func() time.Time { return time.Unix(0, 0) }

	if err := lim.Allow("203.0.113.9:54321", ""); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow("203.0.113.9:54322", ""); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow("203.0.113.9:54323", ""); err != ErrRateLimited {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if err := lim.Allow("198.51.100.1:54321", ""); err != nil {
		t.Fatal(err)
	}

	lim.now = func() time.Time { return time.Unix(0, 0).Add(time.Minute) }
	if err := lim.Allow("203.0.113.9:54321", ""); err != nil {
		t.Fatalf("window reset: %v", err)
	}
}

func TestConnRateLimiterPerOrg(t *testing.T) {
	lim := NewConnRateLimiter(0, 2).(*connRateLimiter)
	lim.now = func() time.Time { return time.Unix(0, 0) }

	if err := lim.Allow("203.0.113.1:1", "org-a"); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow("203.0.113.2:1", "org-a"); err != nil {
		t.Fatal(err)
	}
	if err := lim.Allow("203.0.113.3:1", "org-a"); err != ErrRateLimited {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if err := lim.Allow("203.0.113.3:1", "org-b"); err != nil {
		t.Fatal(err)
	}
}

func TestNewConnRateLimiterNilWhenDisabled(t *testing.T) {
	if NewConnRateLimiter(0, 0) != nil {
		t.Fatal("expected nil limiter when both limits are zero")
	}
}
