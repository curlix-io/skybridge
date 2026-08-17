// Command metadata-discovery-e2e is a throwaway stand-in for the Connector Gateway, used only by
// examples/metadata-discovery-e2e/run-e2e.sh. It plays the SaaS-side role in the metadata discovery
// flow documented in docs/METADATA_DISCOVERY.md: accept one edge's Connect stream, dispatch a
// MetadataDiscoveryRequest per configured driver, and check that the matching
// MetadataDiscoveryResponse reports the seeded "customers" table/collection.
//
// This is deliberately not a `go test` — it drives a real `skybridge edge` process against real
// Postgres/MySQL/MongoDB containers over the real gRPC Connect stream, which the hermetic
// in-process tests under internal/edge/{dbquery,transport} intentionally do not exercise (see
// CLAUDE.md's testing contract: unit tests stay hermetic, this script is the deliberate exception
// for a manual end-to-end run).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
)

// driverExpectation is one metadata-discovery round trip to run against the edge under test.
type driverExpectation struct {
	driver string
	object string // object_name expected somewhere in the response
}

func main() {
	listen := flag.String("listen", ":17100", "address to accept the edge's Connect stream on")
	accountKey := flag.String("account", "e2e-account", "account_key to send in each MetadataDiscoveryRequest")
	database := flag.String("database", "appdb", "database_name to send in each MetadataDiscoveryRequest")
	timeout := flag.Duration("timeout", 30*time.Second, "max time to wait for the whole run")
	flag.Parse()

	expectations := []driverExpectation{
		{driver: "postgres", object: "customers"},
		{driver: "mysql", object: "customers"},
		{driver: "mongo", object: "customers"},
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}

	result := make(chan error, 1)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, &fakeGateway{
		accountKey:   *accountKey,
		database:     *database,
		expectations: expectations,
		result:       result,
	})

	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Printf("grpc serve ended: %v", err)
		}
	}()
	defer srv.Stop()

	select {
	case err := <-result:
		if err != nil {
			fmt.Println("FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("PASS: all drivers reported the seeded object")
	case <-time.After(*timeout):
		fmt.Println("FAIL: timed out waiting for the edge to connect and respond")
		os.Exit(1)
	}
}

type fakeGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	accountKey   string
	database     string
	expectations []driverExpectation
	result       chan error
}

func (g *fakeGateway) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		g.result <- fmt.Errorf("waiting for Register: %w", err)
		return err
	}
	reg := first.GetRegister()
	if reg == nil {
		err := errors.New("expected Register as the first message")
		g.result <- err
		return err
	}
	log.Printf("edge registered: tenant=%s connector=%s", reg.GetTenantId(), reg.GetConnectorId())

	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Registered{Registered: &connectorv1.Registered{SessionId: "e2e-session"}},
	}); err != nil {
		g.result <- err
		return err
	}

	for i, exp := range g.expectations {
		requestID := fmt.Sprintf("req-%d-%s", i, exp.driver)
		log.Printf("dispatching metadata discovery: driver=%s database=%s", exp.driver, g.database)
		if err := stream.Send(&connectorv1.GatewayMessage{
			Msg: &connectorv1.GatewayMessage_MetadataDiscoveryRequest{MetadataDiscoveryRequest: &connectorv1.MetadataDiscoveryRequest{
				RequestId:    requestID,
				AccountKey:   g.accountKey,
				Driver:       exp.driver,
				DatabaseName: g.database,
			}},
		}); err != nil {
			g.result <- err
			return err
		}

		resp, err := g.awaitResponse(stream, requestID)
		if err != nil {
			g.result <- err
			return err
		}
		if !resp.GetSuccess() {
			err := fmt.Errorf("driver=%s: discovery failed: %s", exp.driver, resp.GetError())
			g.result <- err
			return err
		}
		if !containsObject(resp.GetObjects(), exp.object) {
			err := fmt.Errorf("driver=%s: expected object %q, got %v", exp.driver, exp.object, resp.GetObjects())
			g.result <- err
			return err
		}
		log.Printf("driver=%s: OK, discovered %d object(s)", exp.driver, len(resp.GetObjects()))
	}

	g.result <- nil
	return nil
}

// awaitResponse drains inbound messages until it sees a MetadataDiscoveryResponse matching
// requestID (there is only ever one edge connected, so this never needs to buffer anything else).
func (g *fakeGateway) awaitResponse(stream connectorv1.ConnectorGateway_ConnectServer, requestID string) (*connectorv1.MetadataDiscoveryResponse, error) {
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("stream closed while waiting for response to %s", requestID)
			}
			return nil, err
		}
		resp := msg.GetMetadataDiscoveryResponse()
		if resp == nil {
			continue
		}
		if resp.GetRequestId() != requestID {
			continue
		}
		return resp, nil
	}
}

func containsObject(objects []*connectorv1.DatabaseObject, name string) bool {
	for _, o := range objects {
		if o.GetObjectName() == name {
			return true
		}
	}
	return false
}
