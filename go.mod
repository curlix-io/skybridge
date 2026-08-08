// Skybridge — a Go data plane for governed native database access. An egress-only agent terminates
// native client wire protocols (psql / mysql / mongosh), masks PII locally before any bytes leave
// the network, and (optionally) reports sessions to a relay gateway + external control plane.
//
// Pure standard library on purpose: manual wire parsing + masking over net/http, so `go build`
// works offline with no third-party module downloads.
module github.com/curlix-io/skybridge

go 1.26

require (
	github.com/aws/aws-sdk-go-v2 v1.43.2
	github.com/aws/aws-sdk-go-v2/config v1.32.25
	github.com/aws/aws-sdk-go-v2/credentials v1.19.24
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.59.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.78.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.85.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.55.4
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.3
	github.com/go-sql-driver/mysql v1.10.0
	github.com/jackc/pgx/v5 v5.10.0
	go.mongodb.org/mongo-driver v1.17.9
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.13 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.6 // indirect
	github.com/aws/smithy-go v1.27.5 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)
