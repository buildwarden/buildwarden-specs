package upstream

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
	"net/netip"
	"time"
)

// CA is the certificate authority of the harness's origin servers. A claim
// carries its certificate in upstream_ca_certs, with upstream_system_ca
// false, so that a relay trusts the origins and nothing else (relay-claim).
// It is made for one harness run and signs only the origins' leaves.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// Validity of the authority and its leaves, around the time they are made.
// They are constants of a harness release.
const (
	// notBefore is how far before its making a certificate is valid, so
	// that a relay whose clock is a little behind accepts it.
	notBefore = time.Hour
	// lifetime is how long after its making a certificate stays valid.
	lifetime = 24 * time.Hour
)

// NewCA makes an authority with a fresh ECDSA P-256 key.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("upstream: the origin CA's key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "BuildWarden conformance origin CA"},
		NotBefore:             now.Add(-notBefore),
		NotAfter:              now.Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("upstream: the origin CA's certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("upstream: the origin CA's certificate: %w", err)
	}
	return &CA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// PEM is the authority's certificate, PEM-encoded: one entry of a claim's
// upstream_ca_certs.
func (c *CA) PEM() []byte { return append([]byte(nil), c.pem...) }

// Certificate is the authority's certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// Pool is a pool that holds the authority alone.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Leaf issues a server certificate for names, each a DNS name or an IP
// address, with a fresh key, for TLS on an origin.
func (c *CA) Leaf(names ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("upstream: a leaf's key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-notBefore),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(names) > 0 {
		tmpl.Subject = pkix.Name{CommonName: names[0]}
	}
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("upstream: a leaf for %v: %w", names, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("upstream: a leaf for %v: %w", names, err)
	}
	return tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func serialNumber() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("upstream: a serial number: %w", err)
	}
	return n, nil
}
