package spoke

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/pki"
	"agenttrap/internal/protocol"
	"agenttrap/internal/worldpack"
)

// Files kept in the spoke data directory. The private key never leaves it.
const (
	keyFile    = "spoke.key"
	certFile   = "spoke.crt"
	identFile  = "identity.json"
	configFile = "config.json"
)

// identity is the persistent part of the enrollment bundle (no token).
type identity struct {
	SpokeID       string `json:"spoke_id"`
	HubURL        string `json:"hub_url"`
	CAPEM         string `json:"ca_pem"`
	PackPublicKey []byte `json:"pack_public_key"`
}

// Client talks to the hub over mTLS, pinning the hub CA.
type Client struct {
	dir   string
	ident identity
	log   *slog.Logger
	http  *http.Client

	mu   sync.RWMutex
	cert *tls.Certificate
}

// Connect loads the spoke identity from dir, enrolling with bundlePath first
// if the spoke has no certificate yet.
func Connect(ctx context.Context, dir, bundlePath string, log *slog.Logger) (*Client, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &Client{dir: dir, log: log}
	identData, err := os.ReadFile(filepath.Join(dir, identFile))
	switch {
	case err == nil:
		if err := json.Unmarshal(identData, &c.ident); err != nil {
			return nil, fmt.Errorf("spoke: identity: %w", err)
		}
		if err := c.initHTTP(); err != nil {
			return nil, err
		}
		if err := c.loadCert(); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		if err := c.enroll(ctx, bundlePath); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return c, nil
}

func (c *Client) initHTTP() error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.ident.CAPEM)) {
		return errors.New("spoke: invalid hub CA")
	}
	u, err := url.Parse(c.ident.HubURL)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("spoke: hub URL must be https: %q", c.ident.HubURL)
	}
	c.http = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots, // pinned: the system store is never consulted
				ServerName: u.Hostname(),
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					c.mu.RLock()
					defer c.mu.RUnlock()
					if c.cert == nil {
						return &tls.Certificate{}, nil
					}
					return c.cert, nil
				},
			},
			ForceAttemptHTTP2: true,
		},
	}
	return nil
}

func (c *Client) enroll(ctx context.Context, bundlePath string) error {
	if bundlePath == "" {
		return errors.New("spoke: not enrolled and no enrollment bundle given")
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("spoke: reading bundle: %w", err)
	}
	var b protocol.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("spoke: bundle: %w", err)
	}
	c.ident = identity{SpokeID: b.SpokeID, HubURL: b.HubURL, CAPEM: b.CAPEM, PackPublicKey: b.PackPublicKey}
	if err := c.initHTTP(); err != nil {
		return err
	}
	keyPEM, csrPEM, err := pki.NewKeyAndCSR()
	if err != nil {
		return err
	}
	var resp protocol.CertResponse
	if err := c.post(ctx, "/v1/enroll", protocol.EnrollRequest{Token: b.Token, CSRPEM: string(csrPEM)}, &resp); err != nil {
		return fmt.Errorf("spoke: enrollment: %w", err)
	}
	if err := c.storeCert(keyPEM, []byte(resp.CertPEM)); err != nil {
		return err
	}
	identData, _ := json.Marshal(c.ident)
	if err := writeFileAtomic(filepath.Join(c.dir, identFile), identData); err != nil {
		return err
	}
	c.log.Info("enrolled with hub", "spoke", c.ident.SpokeID)
	return nil
}

func (c *Client) loadCert() error {
	keyPEM, err := os.ReadFile(filepath.Join(c.dir, keyFile))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(filepath.Join(c.dir, certFile))
	if err != nil {
		return err
	}
	return c.setCert(keyPEM, certPEM)
}

func (c *Client) setCert(keyPEM, certPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("spoke: certificate: %w", err)
	}
	c.mu.Lock()
	c.cert = &cert
	c.mu.Unlock()
	// Pooled connections were authenticated with the previous certificate
	// (or none, during enrollment); drop them so the new one is presented.
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
	return nil
}

func (c *Client) storeCert(keyPEM, certPEM []byte) error {
	if err := c.setCert(keyPEM, certPEM); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(c.dir, keyFile), keyPEM); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.dir, certFile), certPEM)
}

// SpokeID returns this spoke's identity.
func (c *Client) SpokeID() string { return c.ident.SpokeID }

// CertExpiry returns when the current client certificate expires.
func (c *Client) CertExpiry() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil || c.cert.Leaf == nil {
		return time.Time{}
	}
	return c.cert.Leaf.NotAfter
}

// Renew rotates the key and certificate when less than half the lifetime
// remains (or always, if force is set).
func (c *Client) Renew(ctx context.Context, force bool) error {
	c.mu.RLock()
	leaf := c.cert.Leaf
	c.mu.RUnlock()
	if !force && leaf != nil {
		half := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
		if time.Now().Before(half) {
			return nil
		}
	}
	keyPEM, csrPEM, err := pki.NewKeyAndCSR()
	if err != nil {
		return err
	}
	var resp protocol.CertResponse
	if err := c.post(ctx, "/v1/renew", protocol.RenewRequest{CSRPEM: string(csrPEM)}, &resp); err != nil {
		return err
	}
	if err := c.storeCert(keyPEM, []byte(resp.CertPEM)); err != nil {
		return err
	}
	c.log.Info("renewed spoke certificate", "expires", c.CertExpiry())
	return nil
}

// Config fetches this spoke's canary seed and verified world pack, falling
// back to the last cached copy if the hub is unreachable.
func (c *Client) Config(ctx context.Context) (*worldpack.Pack, []byte, error) {
	path := filepath.Join(c.dir, configFile)
	var cfg protocol.ConfigResponse
	err := c.get(ctx, "/v1/config", &cfg)
	if err == nil {
		data, _ := json.Marshal(cfg)
		if werr := writeFileAtomic(path, data); werr != nil {
			return nil, nil, werr
		}
	} else {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, nil, fmt.Errorf("spoke: hub unreachable and no cached config: %w", err)
		}
		c.log.Warn("hub unreachable, using cached config", "err", err)
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, nil, err
		}
	}
	pack, err := worldpack.Open(c.ident.PackPublicKey, cfg.Pack)
	if err != nil {
		return nil, nil, err
	}
	return pack, cfg.CanarySeed, nil
}

// SendBatch ships one batch of events.
func (c *Client) SendBatch(ctx context.Context, b events.Batch) error {
	var resp protocol.IngestResponse
	return c.post(ctx, "/v1/events", b, &resp)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ident.HubURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ident.HubURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("hub %s: %s: %s", req.URL.Path, resp.Status, bytes.TrimSpace(msg))
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity {
			err = fmt.Errorf("%w: %w", ErrRejected, err)
		}
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
