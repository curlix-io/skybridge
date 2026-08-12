package main

import (
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
)

func TestDistinctClientOrgsCountsUniqueNonEmptyOrgIDs(t *testing.T) {
	cases := []struct {
		name    string
		clients []config.ClientListener
		want    int
	}{
		{"no clients", nil, 0},
		{"single org", []config.ClientListener{{OrgID: "org-a"}}, 1},
		{"same org twice", []config.ClientListener{{OrgID: "org-a"}, {OrgID: "org-a"}}, 1},
		{"two distinct orgs", []config.ClientListener{{OrgID: "org-a"}, {OrgID: "org-b"}}, 2},
		{"empty org_id not counted", []config.ClientListener{{OrgID: ""}, {OrgID: "org-a"}}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := distinctClientOrgs(c.clients); got != c.want {
				t.Fatalf("distinctClientOrgs(%v) = %d, want %d", c.clients, got, c.want)
			}
		})
	}
}
