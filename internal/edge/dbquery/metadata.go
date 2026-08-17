package dbquery

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DiscoverDatabaseMetadata discovers schema objects in the target database.
// It returns a list of DatabaseObject entries for tables, views, functions, etc.
func DiscoverDatabaseMetadata(
	ctx context.Context,
	driver string,
	target Target,
	database string,
) ([]*connectorv1.DatabaseObject, error) {
	driver = strings.ToLower(strings.TrimSpace(driver))
	database = strings.TrimSpace(database)

	if database == "" {
		database = strings.TrimSpace(target.DatabaseName)
	}

	switch driver {
	case "postgres":
		return discoverPostgresMetadata(ctx, target, database)
	case "mysql":
		return discoverMysqlMetadata(ctx, target, database)
	case "mongo", "mongodb":
		return discoverMongoMetadata(ctx, target, database)
	default:
		return nil, fmt.Errorf("metadata discovery not supported for driver: %s", driver)
	}
}

// discoverPostgresMetadata discovers tables, views, and other objects in Postgres.
func discoverPostgresMetadata(ctx context.Context, target Target, database string) ([]*connectorv1.DatabaseObject, error) {
	user, pass := creds(target, "", "")
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil, fmt.Errorf("postgres target missing host")
	}

	sslmode := strings.TrimSpace(target.SSLMode)
	if sslmode == "" {
		sslmode = "require"
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		urlEscape(user), urlEscape(pass), host, database, sslmode)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Query to get tables, views, materialized views, and sequences
	query := `
		SELECT
			n.nspname AS schema_name,
			c.relname AS object_name,
			c.relkind AS kind
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'v', 'm', 'f', 'S')
			AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			AND n.nspname NOT LIKE 'pg_toast%'
		ORDER BY n.nspname, c.relname
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var objects []*connectorv1.DatabaseObject
	for rows.Next() {
		var schema, name, kind string
		if err := rows.Scan(&schema, &name, &kind); err != nil {
			return nil, err
		}
		objects = append(objects, &connectorv1.DatabaseObject{
			SchemaName: schema,
			ObjectName: name,
			Kind:       kind,
		})
	}

	return objects, rows.Err()
}

// discoverMysqlMetadata discovers tables and views in MySQL.
func discoverMysqlMetadata(ctx context.Context, target Target, database string) ([]*connectorv1.DatabaseObject, error) {
	user, pass := creds(target, "", "")
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil, fmt.Errorf("mysql target missing host")
	}
	// If host doesn't include a port, append the default MySQL port
	if !strings.Contains(host, ":") {
		host = host + ":3306"
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&timeout=30s&interpolateParams=true",
		urlEscape(user), urlEscape(pass), host, database)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Query to get tables and views
	query := `
		SELECT
			TABLE_SCHEMA AS schema_name,
			TABLE_NAME AS object_name,
			CASE WHEN TABLE_TYPE = 'VIEW' THEN 'v' ELSE 'r' END AS kind
		FROM INFORMATION_SCHEMA.TABLES
		WHERE TABLE_SCHEMA = ?
			AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		ORDER BY TABLE_SCHEMA, TABLE_NAME
	`

	rows, err := db.QueryContext(ctx, query, database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var objects []*connectorv1.DatabaseObject
	for rows.Next() {
		var schema, name, kind string
		if err := rows.Scan(&schema, &name, &kind); err != nil {
			return nil, err
		}
		objects = append(objects, &connectorv1.DatabaseObject{
			SchemaName: schema,
			ObjectName: name,
			Kind:       kind,
		})
	}

	return objects, rows.Err()
}

// discoverMongoMetadata discovers collections in MongoDB.
func discoverMongoMetadata(ctx context.Context, target Target, database string) ([]*connectorv1.DatabaseObject, error) {
	user, pass := creds(target, "", "")
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil, fmt.Errorf("mongo target missing host")
	}
	// If host doesn't include a port, append the default MongoDB port
	if !strings.Contains(host, ":") {
		host = host + ":27017"
	}

	// Build URI
	var uri string
	if user != "" && pass != "" {
		uri = fmt.Sprintf("mongodb://%s:%s@%s/%s?serverSelectionTimeoutMS=5000",
			urlEscape(user), urlEscape(pass), host, database)
	} else {
		uri = fmt.Sprintf("mongodb://%s/%s?serverSelectionTimeoutMS=5000",
			host, database)
	}

	clientOpts := options.Client().ApplyURI(uri).SetConnectTimeout(15 * time.Second)
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(ctx)

	db := client.Database(database)

	// List collections
	colls, err := db.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return nil, err
	}

	var objects []*connectorv1.DatabaseObject
	for _, collName := range colls {
		objects = append(objects, &connectorv1.DatabaseObject{
			SchemaName: database,
			ObjectName: collName,
			Kind:       "collection", // MongoDB uses 'collection' kind
		})
	}

	return objects, nil
}
