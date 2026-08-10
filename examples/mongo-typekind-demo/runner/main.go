// Command mongo-typekind-demo-runner connects to a real skybridge-agent (mongo mode) in front of a
// real MongoDB, queries the seeded "users" collection through it, and asserts the confirmed-label
// redaction on the BSON datetime field "dob" actually took effect end to end — proving
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B Mongo fix against real infrastructure, not just
// the unit tests in internal/wire/mongo/bson_typekind_test.go.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	agentURI := os.Getenv("AGENT_MONGO_URI")
	if agentURI == "" {
		agentURI = "mongodb://agent:27020"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	client := mustConnect(ctx, agentURI)
	defer client.Disconnect(context.Background())

	// The confirmed label the stub control plane serves doesn't take effect immediately: the
	// agent's remotestore.Store only pulls it on its next poll tick
	// (SKYBRIDGE_PATH_LABEL_POLL_SECONDS, floored at remotestore.minPollSeconds=15s), and only
	// after this query's own first Lookup calls SeedObject to register the ObjectID with the
	// poller at all. So this retries the query itself until the redaction is observed, rather than
	// assuming the label is live on the first attempt — that propagation delay is real, documented
	// behavior (see remotestore.go's Start/refreshPull), not a bug in the runner.
	var doc bson.M
	var lastDobStr string
	redacted := false
	for !redacted {
		select {
		case <-ctx.Done():
			fmt.Printf("FAIL: timed out waiting for the confirmed label to take effect; last dob seen: %s\n", lastDobStr)
			os.Exit(1)
		default:
		}

		doc = bson.M{}
		if err := client.Database("appdb").Collection("users").FindOne(ctx, bson.M{"_id": int32(1)}).Decode(&doc); err != nil {
			log.Fatalf("query through agent failed: %v", err)
		}
		if dob, ok := doc["dob"].(primitive.DateTime); ok {
			lastDobStr = dob.Time().String()
			if dob.Time().Unix() == 0 {
				redacted = true
				break
			}
		}
		fmt.Printf("waiting for the confirmed label to propagate (dob still raw: %s)...\n", lastDobStr)
		time.Sleep(2 * time.Second)
	}

	fmt.Printf("Document received through skybridge-agent: %+v\n\n", doc)

	pass := true

	name, _ := doc["name"].(string)
	if name != "Alice Smith" {
		fmt.Printf("FAIL: expected control field name=%q untouched, got %q\n", "Alice Smith", name)
		pass = false
	} else {
		fmt.Println("PASS: control field 'name' passed through untouched")
	}

	dob, dobIsDate := doc["dob"].(primitive.DateTime)
	switch {
	case !dobIsDate:
		fmt.Printf("FAIL: expected 'dob' to still decode as a BSON datetime, got %T\n", doc["dob"])
		pass = false
	case dob.Time().Unix() != 0:
		fmt.Printf("FAIL: expected 'dob' redacted to the zero-valued epoch datetime, got %v\n", dob.Time())
		pass = false
	default:
		fmt.Println("PASS: typed field 'dob' redacted to the zero-valued epoch datetime (Gap B fix confirmed)")
	}

	if !pass {
		os.Exit(1)
	}
	fmt.Println("\nEnd-to-end Mongo TypeKind redaction test PASSED.")
}

// mustConnect retries the initial ping for up to ~30s — the agent container has no healthcheck
// (its distroless base image has no shell to probe with), so the runner absorbs the startup race
// itself instead.
func mustConnect(ctx context.Context, uri string) *mongo.Client {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	var lastErr error
	for i := 0; i < 30; i++ {
		if lastErr = client.Ping(ctx, nil); lastErr == nil {
			return client
		}
		time.Sleep(time.Second)
	}
	log.Fatalf("ping through agent (after retries): %v", lastErr)
	return nil
}
