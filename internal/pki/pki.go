// Package pki implements the private CA used only for spoke<->hub mTLS.
//
// Layout: an offline root signs an online intermediate; the intermediate issues
// short-lived spoke client certificates and the hub server certificate. These
// certificates are never used for public facade TLS.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const spokeURIPrefix = "urn:agenttrap:spoke:"

// File names inside a PKI directory.
const (
	RootCertFile         = "root.crt"
	RootKeyFile          = "root.key"
	IntermediateCertFile = "intermediate.crt"
	IntermediateKeyFile  = "intermediate.key"
	PackKeyFile          = "pack.key"
)

var spokeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidSpokeID reports whether id is an acceptable spoke identifier.
func ValidSpokeID(id string) bool { return spokeIDPattern.MatchString(id) }

// Init creates a root CA, an intermediate CA and a world-pack signing key in dir.
// It refuses to overwrite an existing CA.
func Init(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, IntermediateCertFile)); err == nil {
		return fmt.Errorf("pki: CA already exists in %s", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	now := time.Now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "AgentTrap Spoke Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "AgentTrap Spoke Intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	_, packKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{RootCertFile, pemBlock("CERTIFICATE", rootDER), 0o644},
		{RootKeyFile, mustKeyPEM(rootKey), 0o600},
		{IntermediateCertFile, pemBlock("CERTIFICATE", intDER), 0o644},
		{IntermediateKeyFile, mustKeyPEM(intKey), 0o600},
		{PackKeyFile, mustKeyPEM(packKey), 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// Issuer signs certificates with the intermediate CA.
type Issuer struct {
	RootPEM []byte
	Roots   *x509.CertPool
	intCert *x509.Certificate
	intPEM  []byte
	intKey  crypto.Signer
	PackKey ed25519.PrivateKey
}

// LoadIssuer loads the intermediate CA and pack key from dir. The root private
// key is not needed and should be moved offline after Init.
func LoadIssuer(dir string) (*Issuer, error) {
	rootPEM, err := os.ReadFile(filepath.Join(dir, RootCertFile))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("pki: invalid root certificate")
	}
	intPEM, err := os.ReadFile(filepath.Join(dir, IntermediateCertFile))
	if err != nil {
		return nil, err
	}
	intCert, err := ParseCertPEM(intPEM)
	if err != nil {
		return nil, err
	}
	intKey, err := readKey(filepath.Join(dir, IntermediateKeyFile))
	if err != nil {
		return nil, err
	}
	signer, ok := intKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("pki: intermediate key is not a signer")
	}
	packAny, err := readKey(filepath.Join(dir, PackKeyFile))
	if err != nil {
		return nil, err
	}
	packKey, ok := packAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("pki: pack key is not ed25519")
	}
	return &Issuer{RootPEM: rootPEM, Roots: roots, intCert: intCert, intPEM: intPEM, intKey: signer, PackKey: packKey}, nil
}

// SignSpoke issues a client certificate for spokeID from a PEM CSR. The
// returned PEM contains the leaf followed by the intermediate.
func (is *Issuer) SignSpoke(csrPEM []byte, spokeID string, ttl time.Duration) ([]byte, error) {
	if !ValidSpokeID(spokeID) {
		return nil, fmt.Errorf("pki: invalid spoke id %q", spokeID)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("pki: invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	u, _ := url.Parse(spokeURIPrefix + spokeID)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "spoke:" + spokeID},
		URIs:         []*url.URL{u},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, is.intCert, csr.PublicKey, is.intKey)
	if err != nil {
		return nil, err
	}
	return append(pemBlock("CERTIFICATE", der), is.intPEM...), nil
}

// ServerCert issues a fresh hub server certificate for the given DNS names.
func (is *Issuer) ServerCert(dnsNames []string, ttl time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "agenttrap-hub"},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, is.intCert, &key.PublicKey, is.intKey)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der, is.intCert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// SpokeID extracts the spoke identity from a verified client certificate.
func SpokeID(cert *x509.Certificate) (string, bool) {
	for _, u := range cert.URIs {
		s := u.String()
		if id, ok := strings.CutPrefix(s, spokeURIPrefix); ok && ValidSpokeID(id) {
			return id, true
		}
	}
	return "", false
}

// NewKeyAndCSR generates a spoke private key and a CSR for it.
func NewKeyAndCSR() (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "spoke"}}, key)
	if err != nil {
		return nil, nil, err
	}
	return mustKeyPEM(key), pemBlock("CERTIFICATE REQUEST", der), nil
}

// CSRForKey creates a new CSR for an existing PEM private key (used on renewal).
func CSRForKey(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("pki: invalid key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "spoke"}}, key)
	if err != nil {
		return nil, err
	}
	return pemBlock("CERTIFICATE REQUEST", der), nil
}

// ParseCertPEM parses the first certificate in a PEM bundle.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("pki: invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pki: invalid key PEM in %s", path)
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func mustKeyPEM(key any) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pemBlock("PRIVATE KEY", der)
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}
