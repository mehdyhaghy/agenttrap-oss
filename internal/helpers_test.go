package internal_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func x509Pool(t *testing.T, caPEM string) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("bad CA PEM")
	}
	return p
}

func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
}
