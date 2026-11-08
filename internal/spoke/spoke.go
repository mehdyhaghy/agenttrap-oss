// Package spoke runs an attacker-facing sensor node: it serves the persona
// facade from a local world pack, queues events on disk and ships them to the
// hub over mTLS. It keeps serving while the hub is unreachable.
package spoke

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"time"

	"agenttrap/adapters/demogpu"
	"agenttrap/internal/canary"
	"agenttrap/internal/ja4"

	"golang.org/x/crypto/ssh"
)

// Config configures a spoke.
type Config struct {
	DataDir        string
	BundlePath     string
	Listen         string         // facade listener; only the edge proxy should reach it
	SensorListen   string         // optional listener for the JA4 packet sensor
	SSHListen      string         // optional SSH decoy listener (empty = disabled)
	SSHRelays      []netip.Prefix // peers allowed to send a PROXY header on the SSH listener
	RedisListen    string         // optional Redis decoy listener (empty = disabled)
	RedisRelays    []netip.Prefix // peers allowed to send a PROXY header on the Redis listener
	PostgresListen string         // optional Postgres decoy listener (empty = disabled)
	PostgresRelays []netip.Prefix
	Facade         demogpu.Options
	ShipInterval   time.Duration
	MaxQueueFiles  int
	// EventBurst / EventRefill cap events per source so a bot flood on any
	// open port cannot fill the queue or database. EventBurst <= 0 disables it.
	EventBurst  int
	EventRefill time.Duration
}

// Run starts the spoke and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if cfg.ShipInterval == 0 {
		cfg.ShipInterval = 2 * time.Second
	}
	if cfg.MaxQueueFiles == 0 {
		cfg.MaxQueueFiles = 20000
	}
	client, err := connectWithRetry(ctx, cfg, log)
	if err != nil {
		return err
	}
	if err := client.Renew(ctx, false); err != nil {
		log.Warn("certificate renewal failed", "err", err, "expires", client.CertExpiry())
	}
	pack, seed, err := client.Config(ctx)
	if err != nil {
		return err
	}
	log.Info("world pack loaded", "spoke", client.SpokeID(), "pack", pack.ID, "version", pack.Version)

	queue, err := NewQueue(filepath.Join(cfg.DataDir, "queue"), cfg.MaxQueueFiles, log)
	if err != nil {
		return err
	}
	var rec recorder = queue
	if cfg.EventBurst > 0 {
		lr := newLimitRecorder(queue, cfg.EventBurst, cfg.EventRefill)
		go sweepBucket(ctx, lr.bucket, cfg.EventRefill)
		rec = lr
		log.Info("per-source event limit on", "burst", cfg.EventBurst, "refill", cfg.EventRefill)
	}
	facade := demogpu.New(pack, canary.NewSet(seed, pack), rec, cfg.Facade)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           facade,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	go queue.Run(ctx, cfg.ShipInterval, client.SendBatch)
	go renewLoop(ctx, client, log)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	if cfg.SensorListen != "" {
		sensor := &http.Server{
			Addr:              cfg.SensorListen,
			Handler:           sensorHandler(facade, cfg.Facade.TrustedProxies, log),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
		}
		go func() {
			<-ctx.Done()
			_ = sensor.Close()
		}()
		go func() {
			log.Info("sensor listening", "addr", cfg.SensorListen)
			if err := sensor.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("sensor listener failed", "err", err)
			}
		}()
	}

	if cfg.SSHListen != "" {
		ln, err := net.Listen("tcp", cfg.SSHListen)
		if err != nil {
			return err
		}
		keys, err := hostKeys(canary.NewSet(seed, pack))
		if err != nil {
			return err
		}
		go func() {
			log.Info("ssh decoy listening", "addr", cfg.SSHListen)
			if err := facade.ServeSSH(ctx, ln, demogpu.SSHOptions{HostKeys: keys, Relays: cfg.SSHRelays}); err != nil {
				log.Error("ssh listener failed", "err", err)
			}
		}()
	}

	if cfg.RedisListen != "" {
		ln, err := net.Listen("tcp", cfg.RedisListen)
		if err != nil {
			return err
		}
		go func() {
			log.Info("redis decoy listening", "addr", cfg.RedisListen)
			if err := facade.ServeRedis(ctx, ln, demogpu.RedisOptions{Relays: cfg.RedisRelays}); err != nil {
				log.Error("redis listener failed", "err", err)
			}
		}()
	}

	if cfg.PostgresListen != "" {
		ln, err := net.Listen("tcp", cfg.PostgresListen)
		if err != nil {
			return err
		}
		go func() {
			log.Info("postgres decoy listening", "addr", cfg.PostgresListen)
			if err := facade.ServePostgres(ctx, ln, demogpu.PostgresOptions{Relays: cfg.PostgresRelays}); err != nil {
				log.Error("postgres listener failed", "err", err)
			}
		}()
	}

	log.Info("facade listening", "addr", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hostKeys derives the SSH decoy's host keys from the spoke's canary seed:
// stable across restarts (a host key that changes is a tell) and different
// per spoke, without storing another secret.
func hostKeys(set *canary.Set) ([]ssh.Signer, error) {
	var out []ssh.Signer
	ed := ed25519.NewKeyFromSeed(set.Subkey("ssh-host-ed25519")[:ed25519.SeedSize])
	s1, err := ssh.NewSignerFromKey(ed)
	if err != nil {
		return nil, err
	}
	out = append(out, s1)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(bytes.Repeat(set.Subkey("ssh-host-ecdsa"), 4)))
	if err != nil {
		return nil, err
	}
	s2, err := ssh.NewSignerFromKey(ec)
	if err != nil {
		return nil, err
	}
	return append(out, s2), nil
}

// sensorHandler accepts TLS fingerprints from the packet sensor, which shares
// the edge proxy's network namespace and therefore its trusted address.
func sensorHandler(facade *demogpu.Server, trusted []netip.Prefix, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sensor/tls", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		addr, err := netip.ParseAddr(host)
		if err != nil || !slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(addr.Unmap()) }) {
			log.Warn("sensor report from untrusted peer", "remote", r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var res ja4.Result
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&res); err != nil || res.Hello == nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		facade.ObserveTLS(res)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// connectWithRetry waits for the hub during first enrollment (e.g. while the
// hub container is still starting).
func connectWithRetry(ctx context.Context, cfg Config, log *slog.Logger) (*Client, error) {
	delay := time.Second
	for {
		c, err := Connect(ctx, cfg.DataDir, cfg.BundlePath, log)
		if err == nil {
			return c, nil
		}
		log.Warn("connecting to hub failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func renewLoop(ctx context.Context, c *Client, log *slog.Logger) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Renew(ctx, false); err != nil {
				log.Warn("certificate renewal failed", "err", err, "expires", c.CertExpiry())
			}
		}
	}
}
