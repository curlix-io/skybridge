package dbquery

import (
	"bufio"
	"context"
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"
)

// ---- minimal BSON element builders, just enough for the fixed reply shapes below ----

func fmCstr(s string) []byte { return append([]byte(s), 0x00) }

func fmEstring(name, val string) []byte {
	e := []byte{0x02}
	e = append(e, fmCstr(name)...)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(len(val)+1))
	v = append(v, val...)
	v = append(v, 0x00)
	return append(e, v...)
}

func fmEint32(name string, val int32) []byte {
	e := []byte{0x10}
	e = append(e, fmCstr(name)...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(val))
	return append(e, b...)
}

func fmEint64(name string, val int64) []byte {
	e := []byte{0x12}
	e = append(e, fmCstr(name)...)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(val))
	return append(e, b...)
}

func fmEdouble(name string, val float64) []byte {
	e := []byte{0x01}
	e = append(e, fmCstr(name)...)
	bits := make([]byte, 8)
	binary.LittleEndian.PutUint64(bits, math.Float64bits(val))
	return append(e, bits...)
}

func fmEbool(name string, val bool) []byte {
	e := []byte{0x08}
	e = append(e, fmCstr(name)...)
	if val {
		e = append(e, 1)
	} else {
		e = append(e, 0)
	}
	return e
}

func fmEnested(typ byte, name string, doc []byte) []byte {
	e := []byte{typ}
	e = append(e, fmCstr(name)...)
	return append(e, doc...)
}

func fmBdoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	out := make([]byte, 4, 5+len(body))
	out = append(out, body...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

func fmOpMsgReply(body []byte, responseTo int32) []byte {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], 2013)
	msg = append(msg, 0) // section kind 0 (body)
	msg = append(msg, body...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// fmOpReply builds a legacy OP_REPLY (opcode 1) — the driver's initial handshake still uses
// OP_QUERY/OP_REPLY (not OP_MSG) against a server whose wire version isn't known yet.
func fmOpReply(doc []byte, responseTo int32) []byte {
	msg := make([]byte, 16)
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], 1)
	msg = append(msg, 0, 0, 0, 0)             // responseFlags
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0) // cursorID
	msg = append(msg, 0, 0, 0, 0)             // startingFrom
	msg = append(msg, 1, 0, 0, 0)             // numberReturned
	msg = append(msg, doc...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

func fmReadMsg(br *bufio.Reader) (requestID int32, opcode int32, body []byte, ok bool) {
	hdr := make([]byte, 16)
	if !fakePGReadFull(br, hdr) {
		return 0, 0, nil, false
	}
	length := binary.LittleEndian.Uint32(hdr[0:4])
	requestID = int32(binary.LittleEndian.Uint32(hdr[4:8]))
	opcode = int32(binary.LittleEndian.Uint32(hdr[12:16]))
	rest := make([]byte, int(length)-16)
	if !fakePGReadFull(br, rest) {
		return 0, 0, nil, false
	}
	return requestID, opcode, rest, true
}

func fmHelloReply() []byte {
	return fmBdoc(
		fmEbool("ismaster", true),
		fmEint32("maxWireVersion", 21),
		fmEint32("minWireVersion", 0),
		fmEint32("maxBsonObjectSize", 16777216),
		fmEint32("maxMessageSizeBytes", 48000000),
		fmEint32("maxWriteBatchSize", 100000),
		fmEint32("logicalSessionTimeoutMinutes", 30),
		fmEdouble("ok", 1),
	)
}

// fmContains does a raw substring search over an encoded BSON command document — good enough to
// route a fixed, test-authored request shape by command name without fully decoding BSON.
func fmContains(body []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(body); i++ {
		if string(body[i:i+len(n)]) == needle {
			return true
		}
	}
	return false
}

// fakeMongoServerOpts configures fakeMongoServer's canned command replies.
type fakeMongoServerOpts struct {
	// findDocs/aggDocs are the field=value pairs (as alternating name/value pairs collapsed into a
	// single fmEstring per doc) returned as the sole batch for a find/aggregate command.
	findNote string
	aggNote  string
	// listCollNames, when non-empty, answers a listCollections command with one {name: ...}
	// document per entry, in order — drives discoverMongoMetadata's ListCollectionNames call.
	listCollNames []string
}

// fakeMongoServer speaks just enough of the MongoDB wire protocol (legacy OP_QUERY/OP_REPLY for
// the initial handshake, OP_MSG for everything after wire version negotiation) to drive
// executeMongo/executeWriteMongo's success paths hermetically — no real MongoDB server, per
// CLAUDE.md's testing guidance. Command routing is a raw substring match on the command name
// rather than full BSON decoding, since every request shape here is fixed and test-authored.
func fakeMongoServer(t *testing.T, opts fakeMongoServerOpts) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fmServeConn(conn, opts)
		}
	}()
	return ln.Addr().String()
}

func fmServeConn(conn net.Conn, opts fakeMongoServerOpts) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		reqID, opcode, body, ok := fmReadMsg(br)
		if !ok {
			return
		}
		if opcode == 2004 { // legacy OP_QUERY handshake
			_, _ = conn.Write(fmOpReply(fmHelloReply(), reqID))
			continue
		}
		switch {
		case fmContains(body, "listCollections") && len(opts.listCollNames) > 0:
			docs := make([][]byte, 0, len(opts.listCollNames))
			for i, name := range opts.listCollNames {
				doc := fmBdoc(fmEstring("name", name), fmEstring("type", "collection"))
				docs = append(docs, fmEnested(0x03, itoaFakePG(i), doc))
			}
			batch := fmBdoc(docs...)
			cursor := fmBdoc(fmEnested(0x04, "firstBatch", batch), fmEstring("ns", "db.$cmd.listCollections"), fmEint64("id", 0))
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEnested(0x03, "cursor", cursor), fmEdouble("ok", 1)), reqID))
		case fmContains(body, "find") && opts.findNote != "":
			batch := fmBdoc(fmEnested(0x03, "0", fmBdoc(fmEstring("note", opts.findNote))))
			cursor := fmBdoc(fmEnested(0x04, "firstBatch", batch), fmEstring("ns", "db.users"), fmEint64("id", 0))
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEnested(0x03, "cursor", cursor), fmEdouble("ok", 1)), reqID))
		case fmContains(body, "aggregate") && opts.aggNote != "":
			batch := fmBdoc(fmEnested(0x03, "0", fmBdoc(fmEstring("note", opts.aggNote))))
			cursor := fmBdoc(fmEnested(0x04, "firstBatch", batch), fmEstring("ns", "db.orders"), fmEint64("id", 0))
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEnested(0x03, "cursor", cursor), fmEdouble("ok", 1)), reqID))
		case fmContains(body, "aggregate"):
			batch := fmBdoc()
			cursor := fmBdoc(fmEnested(0x04, "firstBatch", batch), fmEstring("ns", "db.users"), fmEint64("id", 0))
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEnested(0x03, "cursor", cursor), fmEdouble("ok", 1)), reqID))
		case fmContains(body, "insert"):
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEint32("n", 1), fmEdouble("ok", 1)), reqID))
		case fmContains(body, "update"):
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEint32("n", 1), fmEint32("nModified", 1), fmEdouble("ok", 1)), reqID))
		case fmContains(body, "delete"):
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEint32("n", 1), fmEdouble("ok", 1)), reqID))
		default:
			// hello ping, buildInfo, endSessions, etc: an unconditional ok=1 keeps the client from
			// hanging on a response it will never otherwise get.
			_, _ = conn.Write(fmOpMsgReply(fmBdoc(fmEdouble("ok", 1)), reqID))
		}
	}
}

// TestExecuteMongoFindHappyPathMasksDocuments exercises executeMongo's full find success path
// (dial, cursor decode, normalizeBSONDoc, maskDocuments, flattenBSON) against fakeMongoServer.
func TestExecuteMongoFindHappyPathMasksDocuments(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{findNote: "hello"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spy := &pathSpyMasker{}
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.find({})`, Options{Masker: spy, ApplyPII: true, OrgID: "org1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, ok := res["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results map, got %#v", res)
	}
	data, ok := results["data"].([]map[string]any)
	if !ok || len(data) != 1 {
		t.Fatalf("expected 1 document, got %#v", results["data"])
	}
	if data[0]["note"] != "hello" {
		t.Fatalf("unexpected document: %#v", data[0])
	}
	if len(spy.seen) == 0 {
		t.Fatal("expected maskDocuments to see at least one leaf")
	}
}

// TestExecuteMongoAggregateHappyPath exercises executeMongo's "aggregate" branch (coll.Aggregate)
// success path, which the find-shaped happy-path test above doesn't reach.
func TestExecuteMongoAggregateHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{aggNote: "agg-result"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.orders.aggregate([{"$match":{"a":1}}])`, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].([]map[string]any)
	if len(data) != 1 || data[0]["note"] != "agg-result" {
		t.Fatalf("unexpected aggregate result: %#v", data)
	}
}

// TestExecuteMongoFindRespectsMaxRows exercises the "len(docs) >= limit" early-break branch in
// executeMongo's cursor-drain loop, distinct from the server-side find-limit clamp.
func TestExecuteMongoFindRespectsMaxRows(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{findNote: "capped"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.find({})`, Options{MaxRows: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].([]map[string]any)
	if len(data) != 1 {
		t.Fatalf("expected 1 document, got %d", len(data))
	}
}

// TestExecuteWriteMongoInsertOneHappyPath exercises executeWriteMongo's dial + runMongoWrite's
// insertOne success branch against fakeMongoServer.
func TestExecuteWriteMongoInsertOneHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.insertOne({"a":1})`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, ok := res["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results map, got %#v", res)
	}
	data, ok := results["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %#v", results["data"])
	}
	if _, ok := data["inserted_id"]; !ok {
		t.Fatalf("expected inserted_id in write result, got %#v", data)
	}
}

// TestExecuteWriteMongoUpdateOneHappyPath exercises runMongoWrite's updateOne success branch via
// the full Execute(..., Options{Write:true}) entry point.
func TestExecuteWriteMongoUpdateOneHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.updateOne({"_id":1}, {"$set":{"x":1}})`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	if data["matched_count"] != int64(1) || data["modified_count"] != int64(1) {
		t.Fatalf("unexpected update result: %#v", data)
	}
}

// TestExecuteWriteMongoDeleteOneHappyPath exercises runMongoWrite's deleteOne success branch.
func TestExecuteWriteMongoDeleteOneHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.deleteOne({"_id":1})`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	if data["deleted_count"] != int64(1) {
		t.Fatalf("unexpected delete result: %#v", data)
	}
}

// TestExecuteWriteMongoInsertManyHappyPath exercises runMongoWrite's insertMany success branch.
func TestExecuteWriteMongoInsertManyHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.insertMany([{"a":1},{"a":2}])`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	ids, ok := data["inserted_ids"].([]string)
	if !ok {
		t.Fatalf("expected inserted_ids []string, got %#v", data["inserted_ids"])
	}
	_ = ids
}

// TestExecuteWriteMongoAggregateHappyPath exercises runMongoWrite's aggregate branch (a
// $merge/$out-shaped write pipeline whose cursor output is drained and discarded).
func TestExecuteWriteMongoAggregateHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.aggregate([{"$merge":{"into":"out"}}])`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	if data["acknowledged"] != true {
		t.Fatalf("unexpected aggregate write result: %#v", data)
	}
}

// TestExecuteWriteMongoReplaceOneHappyPath exercises runMongoWrite's replaceOne success branch.
func TestExecuteWriteMongoReplaceOneHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.replaceOne({"_id":1}, {"a":1})`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	if data["matched_count"] != int64(1) {
		t.Fatalf("unexpected replace result: %#v", data)
	}
}

// TestExecuteWriteMongoDeleteManyHappyPath exercises runMongoWrite's deleteMany success branch.
func TestExecuteWriteMongoDeleteManyHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.deleteMany({})`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	if data["deleted_count"] != int64(1) {
		t.Fatalf("unexpected deleteMany result: %#v", data)
	}
}

// TestExecuteWriteMongoUpdateManyHappyPath exercises runMongoWrite's updateMany success branch.
func TestExecuteWriteMongoUpdateManyHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Execute(ctx, Target{Host: addr}, "mongo", "db", `db.users.updateMany({}, {"$set":{"x":1}})`, Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].(map[string]any)
	if data["matched_count"] != int64(1) || data["modified_count"] != int64(1) {
		t.Fatalf("unexpected updateMany result: %#v", data)
	}
}
