package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CRLURL is the CRL distribution point every leaf names (GUEST-42), where the
// relay serves its CA's CRL (GUEST-24).
const CRLURL = "http://artifacts/ca.crl"

// CA is the certificate authority the relay creates for one build: its
// certificate is the claim's ca_cert (CLAIM-33), and it signs what the relay
// presents to the build environment (relay-guest-api). It is a CA
// certificate with a path length of 0 that may sign certificates and CRLs,
// valid from an hour before the claim until a day after.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// PEM is the certificate's PEM encoding.
	PEM []byte
	// CRL is the DER of the CA's CRL, made with the CA: it revokes nothing,
	// and its this-update and next-update are the CA's validity, so that it
	// is the same on every request (GUEST-24).
	CRL []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// newCA makes a CA with a fresh ECDSA P-256 key.
func newCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("the build's CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("the build's CA serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "BuildWarden conformance relay CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("the build's CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("the build's CA certificate: %w", err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: cert.NotBefore,
		NextUpdate: cert.NotAfter,
	}, cert, key)
	if err != nil {
		return nil, fmt.Errorf("the build's CA's CRL: %w", err)
	}
	return &CA{
		Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CRL: crl, leaves: map[string]*tls.Certificate{},
	}, nil
}

// Leaf is the certificate the relay presents for the server name a TLS
// client sent (GUEST-42): signed by the CA and sent with the CA's
// certificate after it; the name as its one DNS name, or its one IP address
// when the name is one; server authentication; the CA's CRL as its
// distribution point; and valid for as long as the CA is. One is made for
// each name, the first time it is asked for, with a fresh ECDSA P-256 key.
func (c *CA) Leaf(name string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leaves[name]; ok {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("a leaf's key for %q: %w", name, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("a leaf's serial for %q: %w", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             c.Cert.NotBefore,
		NotAfter:              c.Cert.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{CRLURL},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, fmt.Errorf("a leaf for %q: %w", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("a leaf for %q: %w", name, err)
	}
	l := &tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: key, Leaf: leaf}
	c.leaves[name] = l
	return l, nil
}
