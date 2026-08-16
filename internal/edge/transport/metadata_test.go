package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

// --- a minimal hermetic fake Postgres server, mirroring dbquery's fakepgserver_test.go pattern
// (kept package-local here since transport can't import dbquery's unexported test helpers).

func mdReadFull(r *bufio.Reader, buf []byte) bool {
	n := 0
	for n < len(buf) {
		k, err := r.Read(buf[n:])
		if err != nil {
			return false
		}
		n += k
	}
	return true
}

func mdWriteMsg(w net.Conn, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func mdParamStatus(name, value string) []byte {
	b := append([]byte(name), 0)
	return append(b, append([]byte(value), 0)...)
}

// mdRowDescription builds a RowDescription for the three text columns discoverPostgresMetadata
// scans into (schema_name, object_name, kind).
func mdRowDescription(cols []string) []byte {
	rd := []byte{byte(len(cols) >> 8), byte(len(cols))}
	for _, col := range cols {
		rd = append(rd, []byte(col)...)
		rd = append(rd, 0)
		rd = append(rd, 0, 0, 0, 0)
		rd = append(rd, 0, 0)
		rd = append(rd, 0, 0, 0, 25)
		rd = append(rd, 0, 4)
		rd = append(rd, 0, 0, 0, 0)
		rd = append(rd, 0, 0)
	}
	return rd
}

func mdDataRow(vals ...string) []byte {
	d := []byte{byte(len(vals) >> 8), byte(len(vals))}
	for _, v := range vals {
		l := len(v)
		d = append(d, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
		d = append(d, v...)
	}
	return d
}

// fakePostgresServer speaks just enough of the v3 startup + simple-query protocol to let
// dbquery.DiscoverDatabaseMetadata's postgres path complete against an in-process listener — no
// real Postgres server, per CLAUDE.md's testing guidance.
func fakePostgresServer(t *testing.T, cols []string, rows [][]string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		var lenb [4]byte
		if !mdReadFull(br, lenb[:]) {
			return
		}
		length := binary.BigEndian.Uint32(lenb[:])
		body := make([]byte, int(length)-4)
		if !mdReadFull(br, body) {
			return
		}

		if mdWriteMsg(conn, 'R', []byte{0, 0, 0, 0}) != nil {
			return
		}
		_ = mdWriteMsg(conn, 'S', mdParamStatus("standard_conforming_strings", "on"))
		_ = mdWriteMsg(conn, 'S', mdParamStatus("server_version", "14.0"))
		_ = mdWriteMsg(conn, 'S', mdParamStatus("client_encoding", "UTF8"))
		if mdWriteMsg(conn, 'Z', []byte{'I'}) != nil {
			return
		}

		for {
			typ, err := br.ReadByte()
			if err != nil {
				return
			}
			var mlen [4]byte
			if !mdReadFull(br, mlen[:]) {
				return
			}
			l := binary.BigEndian.Uint32(mlen[:])
			payload := make([]byte, int(l)-4)
			if !mdReadFull(br, payload) {
				return
			}
			if typ != 'Q' {
				continue
			}
			if err := mdWriteMsg(conn, 'T', mdRowDescription(cols)); err != nil {
				return
			}
			for _, row := range rows {
				if err := mdWriteMsg(conn, 'D', mdDataRow(row...)); err != nil {
					return
				}
			}
			if err := mdWriteMsg(conn, 'C', append([]byte("SELECT"), 0)); err != nil {
				return
			}
			if err := mdWriteMsg(conn, 'Z', []byte{'I'}); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

func TestDiscoverMetadataResolvesTargetAndDelegates(t *testing.T) {
	addr := fakePostgresServer(t, []string{"schema_name", "object_name", "kind"}, [][]string{
		{"public", "users", "r"},
	})
	c := New(Config{
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Targets: []dbquery.Target{
			{DBType: "postgres", AWSAccountID: "acct-1", Host: addr, User: "u", Password: "p", SSLMode: "disable&default_query_exec_mode=simple_protocol"},
		},
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	objects, err := c.discoverMetadata(context.Background(), "postgres", "db", "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objects) != 1 || objects[0].GetObjectName() != "users" {
		t.Fatalf("unexpected objects: %#v", objects)
	}
}

func TestDiscoverMetadataNoMatchingTargetErrors(t *testing.T) {
	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := c.discoverMetadata(context.Background(), "postgres", "db", "acct-unknown")
	if err == nil {
		t.Fatal("expected an error when no configured target matches")
	}
}

// fakeGatewayMetadata registers the connector, sends a MetadataDiscoveryRequest, and waits for the
// matching MetadataDiscoveryResponse before ending the stream cleanly.
type fakeGatewayMetadata struct {
	connectorv1.UnimplementedConnectorGatewayServer
	req     *connectorv1.MetadataDiscoveryRequest
	gotReg  chan *connectorv1.Register
	gotResp chan *connectorv1.MetadataDiscoveryResponse
}

func (g *fakeGatewayMetadata) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetRegister() == nil {
		return errors.New("expected Register first")
	}
	g.gotReg <- first.GetRegister()

	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_MetadataDiscoveryRequest{MetadataDiscoveryRequest: g.req},
	}); err != nil {
		return err
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if resp := msg.GetMetadataDiscoveryResponse(); resp != nil {
			select {
			case g.gotResp <- resp:
			default:
			}
			return nil
		}
	}
}

// TestServeHandlesMetadataDiscoveryRequest exercises the full path: a dispatched
// MetadataDiscoveryRequest received over the Connect stream resolves against Config.Targets,
// discovers metadata from a fake database, and sends back a matching, successful
// MetadataDiscoveryResponse.
func TestServeHandlesMetadataDiscoveryRequest(t *testing.T) {
	addr := fakePostgresServer(t, []string{"schema_name", "object_name", "kind"}, [][]string{
		{"public", "orders", "r"},
	})

	fg := &fakeGatewayMetadata{
		req: &connectorv1.MetadataDiscoveryRequest{
			RequestId:    "req-1",
			AccountKey:   "acct-1",
			Driver:       "postgres",
			DatabaseName: "db",
		},
		gotReg:  make(chan *connectorv1.Register, 1),
		gotResp: make(chan *connectorv1.MetadataDiscoveryResponse, 1),
	}

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := New(Config{
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Targets: []dbquery.Target{
			{DBType: "postgres", AWSAccountID: "acct-1", Host: addr, User: "u", Password: "p", SSLMode: "disable&default_query_exec_mode=simple_protocol"},
		},
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true) }()

	select {
	case <-fg.gotReg:
	case <-ctx.Done():
		t.Fatal("never received Register")
	}

	select {
	case resp := <-fg.gotResp:
		if resp.GetRequestId() != "req-1" {
			t.Fatalf("unexpected request id: %+v", resp)
		}
		if !resp.GetSuccess() {
			t.Fatalf("expected success, got error: %s", resp.GetError())
		}
		if len(resp.GetObjects()) != 1 || resp.GetObjects()[0].GetObjectName() != "orders" {
			t.Fatalf("unexpected objects: %+v", resp.GetObjects())
		}
	case <-ctx.Done():
		t.Fatal("never received MetadataDiscoveryResponse")
	}

	cancel()
	<-serveErr
}

// TestServeHandlesMetadataDiscoveryRequestNoTarget confirms an unresolvable account_key produces
// an error MetadataDiscoveryResponse rather than dropping the request.
func TestServeHandlesMetadataDiscoveryRequestNoTarget(t *testing.T) {
	fg := &fakeGatewayMetadata{
		req: &connectorv1.MetadataDiscoveryRequest{
			RequestId:    "req-2",
			AccountKey:   "acct-unknown",
			Driver:       "postgres",
			DatabaseName: "db",
		},
		gotReg:  make(chan *connectorv1.Register, 1),
		gotResp: make(chan *connectorv1.MetadataDiscoveryResponse, 1),
	}

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true) }()

	select {
	case <-fg.gotReg:
	case <-ctx.Done():
		t.Fatal("never received Register")
	}

	select {
	case resp := <-fg.gotResp:
		if resp.GetSuccess() {
			t.Fatalf("expected failure response, got: %+v", resp)
		}
		if resp.GetError() == "" {
			t.Fatal("expected a non-empty error message")
		}
	case <-ctx.Done():
		t.Fatal("never received MetadataDiscoveryResponse")
	}

	cancel()
	<-serveErr
}
