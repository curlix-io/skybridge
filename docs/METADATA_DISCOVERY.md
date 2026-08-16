# Metadata Discovery via Connect Stream

**Status:** Gateway routing implemented in curlix (SaaS). Edge handlers pending.

## Overview

Metadata discovery (schema exploration for Data Studio) has been refactored to use the existing bidirectional Connect stream instead of exposing databases directly to the SaaS backend.

**Architecture:**
```
SaaS Backend → Connector Gateway → Edge (customer network) → Local Database
              (routes via stream)   (executes metadata)
```

## What's Implemented (SaaS Side - curlix repo)

### Proto Changes
- File: `proto/curlix/connector/v1/connector_gateway.proto`
- Added `MetadataDiscoveryRequest` message (gateway → connector)
- Added `MetadataDiscoveryResponse` message (connector → gateway)
- Extended `ConnectorMessage` oneof to include `metadata_discovery_response` (field 4)
- Extended `GatewayMessage` oneof to include `metadata_discovery_request` (field 5)

Message format:
```protobuf
message MetadataDiscoveryRequest {
  string request_id = 1;         // unique identifier for pairing request/response
  string account_key = 2;        // registered account identifier (aws account, env, etc.)
  string driver = 3;             // postgres, mysql, mongo, snowflake, etc.
  string database_name = 4;      // which database to describe
  string object_type = 5;        // optional: "tables", "views", "functions", etc.
}

message MetadataDiscoveryResponse {
  string request_id = 1;         // matches the request this responds to
  bool success = 2;              // whether discovery succeeded
  string error = 3;              // empty on success
  repeated DatabaseObject objects = 4;  // discovered tables/views/functions/etc.
}

message DatabaseObject {
  string schema_name = 1;
  string object_name = 2;
  string kind = 3;               // r=table, v=view, m=matview, f=foreign, S=seq, etc.
}
```

### Gateway Implementation
- File: `integrations/skybridge-gateway/src/curlix/connector/gateway.py`
- `DescribeDatabaseConnection` RPC:
  * Extracts tenant from `x-curlix-organization-id` header
  * Looks up connected edge for that tenant
  * Creates `MetadataDiscoveryRequest` with unique `request_id`
  * Sends request via the edge's Connect stream `outbound` queue
  * Waits for `MetadataDiscoveryResponse` with matching `request_id` (30s timeout)
  * Returns response to SaaS caller
- `pump_inbound()` in `Connect`:
  * Handles incoming `metadata_discovery_response` messages
  * Matches response to pending request by `request_id`
  * Signals waiting RPC caller via `asyncio.Event`

## What Needs Implementation (Edge Side - skybridge repo)

### 1. Handle MetadataDiscoveryRequest on Connect Stream

**File:** `internal/edge/transport/transport.go` (or similar)

The edge's `Client` that dials out to the gateway needs to:

1. Receive `MetadataDiscoveryRequest` messages via the Connect stream
2. Parse the request (extract account_key, driver, database_name)
3. Call the metadata discovery executor (see below)
4. Return `MetadataDiscoveryResponse` with matching `request_id`

```go
// Pseudo-code
case *connectorv1.MetadataDiscoveryRequest:
    response, err := executeMetadataDiscovery(ctx, req.Driver, req.DatabaseName, req.AccountKey)
    msg := &connectorv1.ConnectorMessage{
        Msg: &connectorv1.ConnectorMessage_MetadataDiscoveryResponse{
            MetadataDiscoveryResponse: &connectorv1.MetadataDiscoveryResponse{
                RequestId: req.RequestId,
                Success: err == nil,
                Error: errorString(err),
                Objects: response,
            },
        },
    }
    // Send msg back via stream
```

### 2. Implement Metadata Discovery Executors

**File:** `internal/edge/dbquery/metadata.go` (NEW)

For each supported database driver, implement metadata query execution:

#### Postgres
```sql
-- Get tables and views
SELECT
    n.nspname as schema_name,
    c.relname as object_name,
    c.relkind as kind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'v', 'm', 'f', 'S')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY n.nspname, c.relname;
```

Function signature:
```go
func executePostgresMetadata(
    ctx context.Context,
    target Target,
    database string,
    accountKey string,
) ([]*connectorv1.DatabaseObject, error)
```

#### MySQL
```sql
-- Get tables and views
SELECT
    TABLE_SCHEMA as schema_name,
    TABLE_NAME as object_name,
    CASE WHEN TABLE_TYPE = 'VIEW' THEN 'v' ELSE 'r' END as kind
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME;
```

#### MongoDB
```go
// Use MongoDB client to discover collections
// For each database:
// 1. listCollections()
// 2. For each collection, optionally sample documents to infer fields

client.Database(databaseName).ListCollectionNames(ctx, bson.M{})
```

### 3. Integrate with Existing Registry

The edge's registry already knows:
- Available databases/targets (configured at startup)
- Credentials (from local credential store)
- Connection pooling/caching

Metadata discovery should:
1. Use the same registry to locate credentials
2. Reuse connection pooling where applicable
3. Execute queries in read-only mode
4. Handle permission errors gracefully

### Implementation Checklist

- [ ] Add proto stubs to skybridge
  ```bash
  make gen  # in skybridge repo
  ```

- [ ] Handle `MetadataDiscoveryRequest` in `transport.go`
  - [ ] Extract request fields
  - [ ] Dispatch to appropriate executor based on driver
  - [ ] Build and send `MetadataDiscoveryResponse`

- [ ] Implement metadata executors in `internal/edge/dbquery/metadata.go`
  - [ ] `executePostgresMetadata()`
  - [ ] `executeMysqlMetadata()`
  - [ ] `executeMongoMetadata()`
  - [ ] Helper: resolve credentials from registry
  - [ ] Helper: convert raw results to `DatabaseObject` format

- [ ] Testing
  - [ ] Unit tests with fake database servers (reuse existing fakes)
  - [ ] Integration test: SaaS → gateway → edge → database
  - [ ] Error cases: connection failures, permission denied, timeout

### Example: Postgres Executor

```go
package dbquery

import (
    "context"
    "database/sql"
    
    connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
)

func executePostgresMetadata(
    ctx context.Context,
    registry *edge.Registry,
    accountKey string,
    database string,
) ([]*connectorv1.DatabaseObject, error) {
    // 1. Look up target from registry
    target, err := registry.ResolveTarget(accountKey)
    if err != nil {
        return nil, err
    }
    
    // 2. Get credentials (existing registry lookup)
    creds, err := getPostgresCredentials(ctx, accountKey)
    if err != nil {
        return nil, err
    }
    
    // 3. Open connection
    dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=require",
        creds.Username, creds.Password, target.Host, target.Port, database)
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }
    defer db.Close()
    
    // 4. Execute metadata query
    rows, err := db.QueryContext(ctx, `
        SELECT n.nspname, c.relname, c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'v', 'm', 'f', 'S')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY n.nspname, c.relname
    `)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    // 5. Convert to protobuf format
    var objects []*connectorv1.DatabaseObject
    for rows.Next() {
        var schema, name, kind string
        if err := rows.Scan(&schema, &name, &kind); err != nil {
            return nil, err
        }
        objects = append(objects, &connectorv1.DatabaseObject{
            SchemaName: schema,
            ObjectName: name,
            Kind: kind,
        })
    }
    
    return objects, rows.Err()
}
```

## Data Flow

1. **SaaS Backend** calls `gateway.DescribeDatabaseConnection(account_key, driver, database)`
2. **Gateway** validates request, looks up connected edge, sends `MetadataDiscoveryRequest` via stream
3. **Edge** receives request via Connect stream
4. **Edge** executes metadata queries locally (SHOW TABLES, DESCRIBE, etc.)
5. **Edge** sends back `MetadataDiscoveryResponse` with discovered objects
6. **Gateway** receives response, signals waiting RPC caller
7. **SaaS Backend** returns explorer-formatted response to UI

All traffic flows over the authenticated Connect stream — no new ports or services exposed.

## Testing Strategy

### Unit Tests
```go
func TestExecutePostgresMetadata(t *testing.T) {
    // Use existing fakepostgresserver_test.go pattern
    // Test: SHOW TABLES, schema enumeration, error cases
}

func TestMetadataDiscoveryRequest_Integration(t *testing.T) {
    // Spin up fake gateway + fake database
    // Send MetadataDiscoveryRequest via stream
    // Verify MetadataDiscoveryResponse contains correct objects
}
```

### Integration Test
- Mock SaaS backend calls `gateway.DescribeDatabaseConnection()`
- Edge handles stream message
- Verify correct schema objects returned

## References

- **Proto:** `proto/curlix/connector/v1/connector_gateway.proto`
- **Gateway implementation:** `integrations/skybridge-gateway/src/curlix/connector/gateway.py`
- **Design:** `docs/design/metadata-discovery-implementation-guide.md` (curlix repo)
- **Existing executors:** `internal/edge/dbquery/postgres.go`, `mysql.go`, `mongo.go`
- **Testing patterns:** `internal/edge/dbquery/*_test.go`
