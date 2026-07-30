package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/gateway"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wiremtls"
)

// testCA is a minimal self-signed CA for exercising the wire mTLS path without any Python
// dependency — it signs an agent client cert carrying the wiremtls SPIFFE SAN, mirroring what
// backend/src/curlix/wire_mtls/pki.py does server-side in production.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test wire mTLS CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// issueClientCert signs a fresh keypair carrying the wiremtls SPIFFE SAN for (tenant, agentID) and
// returns the cert+key as a tls.Certificate, plus the PEM bytes.
func (ca *testCA) issueClientCert(t *testing.T, tenant, agentID string) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(wiremtls.SpiffeID("", tenant, agentID))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func (ca *testCA) issueServerCert(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// TestEndToEndTunnelRelayMTLS proves ServeAgent trusts a verified wire-agent client cert's SPIFFE
// identity in place of the plaintext SKYBRIDGE_GW_TOKEN check — Phase 2 of
// docs/design/identity-aware-network-access.md. No token is configured on either side; only the
// cert's tenant/agent identity is used.
func TestEndToEndTunnelRelayMTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t)
	serverCert := ca.issueServerCert(t)
	clientCert := ca.issueClientCert(t, "org-1", "a1")

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "localhost",
	}

	g := gateway.New("", silent()) // no bearer token configured at all
	rec := &recordingStore{}
	g.SetStore(rec)
	g.SetTargetResolver(stubTargetResolver{
		"db": {Name: "db", Addr: "upstream:0", DBType: "upper"},
	})

	agentRaw, gwRaw := net.Pipe()
	agentTLS := tls.Client(agentRaw, clientTLSCfg)
	gwTLS := tls.Server(gwRaw, serverTLSCfg)

	go func() { _ = g.ServeAgent(gwTLS) }()

	cfg := config.Agent{
		Mode: config.ModeTunnel,
		// Deliberately no AgentID/OrgID/Token set here — the cert supplies identity.
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentTLS, cfg, deps, silent()) }()

	if !waitForOrgAgent(g, "org-1", 2*time.Second) {
		t.Fatal("mTLS agent did not register in time")
	}

	clientGW, client := net.Pipe()
	go func() { _ = g.ServeClient(clientGW, "org-1", "db") }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("got %q want PING", got)
	}
	_ = client.Close()
}

// TestServeAgentRejectsCertOrgMismatch proves a registering agent cannot claim an org_id that
// disagrees with its verified client certificate — the cert is authoritative, mirroring the
// connector gateway's Connect servicer (see integrations/skybridge-gateway/src/curlix/connector/
// gateway.py).
func TestServeAgentRejectsCertOrgMismatch(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueServerCert(t)
	clientCert := ca.issueClientCert(t, "org-1", "a1")

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientTLSCfg := &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "localhost"}

	g := gateway.New("", silent())
	agentRaw, gwRaw := net.Pipe()
	agentTLS := tls.Client(agentRaw, clientTLSCfg)
	gwTLS := tls.Server(gwRaw, serverTLSCfg)
	go func() { _ = g.ServeAgent(gwTLS) }()

	cfg := config.Agent{Mode: config.ModeTunnel, OrgID: "org-EVIL", AgentID: "a1"}
	err := agent.ServeTunnelConn(context.Background(), agentTLS, cfg, agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}, silent())
	if err == nil {
		t.Fatal("expected registration rejection when claimed org_id disagrees with the client cert")
	}
}
