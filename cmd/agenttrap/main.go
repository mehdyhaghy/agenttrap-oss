// Command agenttrap runs the hub (private control plane) or a spoke
// (attacker-facing sensor), and manages the spoke CA.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"agenttrap/adapters/demogpu"
	"agenttrap/internal/digest"
	"agenttrap/internal/geo"
	"agenttrap/internal/graph"
	"agenttrap/internal/hub"
	"agenttrap/internal/ja4"
	"agenttrap/internal/pki"
	"agenttrap/internal/rdns"
	"agenttrap/internal/relay"
	"agenttrap/internal/spoke"
	"agenttrap/internal/testsuite"
	"agenttrap/modules/builtin"
	"agenttrap/personas"
)

func main() {
	// Everything the services store, log and serve is UTC regardless of the
	// host's zone; the dashboard converts to the viewer's zone for display.
	time.Local = time.UTC
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "hub":
		err = runHub(ctx, os.Args[2:], log)
	case "spoke":
		err = runSpoke(ctx, os.Args[2:], log)
	case "pki":
		err = runPKI(os.Args[2:])
	case "admin":
		err = runAdmin(ctx, os.Args[2:])
	case "ja4-sensor":
		err = runJA4Sensor(ctx, os.Args[2:], log)
	case "resolver":
		err = runResolver(ctx, os.Args[2:], log)
	case "digest":
		err = runDigest(ctx, os.Args[2:])
	case "export":
		err = runExport(ctx, os.Args[2:])
	case "notify":
		err = runNotify(ctx, os.Args[2:])
	case "relay":
		err = runRelay(ctx, os.Args[2:], log)
	case "testsuite":
		err = runTestSuite(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil && !errors.Is(err, context.Canceled) { // Canceled = normal shutdown
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  agenttrap pki init  --dir DIR
  agenttrap hub       [flags]   (run "agenttrap hub -h")
  agenttrap spoke     [flags]   (run "agenttrap spoke -h")
  agenttrap admin     get|post PATH [JSON]   e.g. admin get /admin/incidents
  agenttrap ja4-sensor [flags]  (Linux, needs CAP_NET_RAW)
  agenttrap resolver  [flags]   reverse-DNS verification for the hub
  agenttrap digest    [flags]   email (or print) the daily findings digest
  agenttrap export    [flags]   write STIX, DNSBL, CSV and JSON Lines snapshots
  agenttrap notify    [flags]   email new contact form messages to the operator
  agenttrap relay     [flags]   forward a public TCP port to an internal decoy (PROXY protocol)
  agenttrap testsuite [flags]   test a persona for honeypot tells and score it (spec §29.10)`)
}

func runPKI(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		usage()
		return errors.New("unknown pki command")
	}
	fs := flag.NewFlagSet("pki init", flag.ExitOnError)
	dir := fs.String("dir", env("AGENTTRAP_PKI_DIR", "pki"), "directory for the CA")
	_ = fs.Parse(args[1:])
	if err := pki.Init(*dir); err != nil {
		return err
	}
	fmt.Printf("CA created in %s. Move %s offline once the hub is running (README: Spoke↔hub PKI).\n", *dir, pki.RootKeyFile)
	return nil
}

func runHub(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("hub", flag.ExitOnError)
	pkiDir := fs.String("pki-dir", env("AGENTTRAP_PKI_DIR", "/var/lib/agenttrap/pki"), "CA directory")
	autoPKI := fs.Bool("auto-pki", env("AGENTTRAP_AUTO_PKI", "") == "true", "create the CA if missing (single-node only)")
	dsn := fs.String("db", env("AGENTTRAP_DB", ""), "PostgreSQL DSN")
	spokeListen := fs.String("spoke-listen", env("AGENTTRAP_SPOKE_LISTEN", ":8443"), "mTLS listener for spokes (private network only)")
	adminListen := fs.String("admin-listen", env("AGENTTRAP_ADMIN_LISTEN", "127.0.0.1:9090"), "admin API listener (loopback/private only)")
	hubURL := fs.String("hub-url", env("AGENTTRAP_HUB_URL", "https://hub:8443"), "URL spokes use to reach the hub")
	names := fs.String("server-names", env("AGENTTRAP_SERVER_NAMES", "hub"), "comma-separated DNS names for the hub certificate")
	adminTokenFile := fs.String("admin-token-file", env("AGENTTRAP_ADMIN_TOKEN_FILE", ""), "file holding the admin bearer token")
	packPath := fs.String("pack", env("AGENTTRAP_PACK", ""), "world pack JSON (default: built-in DemoGPU)")
	bootstrapSpoke := fs.String("bootstrap-spoke", env("AGENTTRAP_BOOTSTRAP_SPOKE", ""), "create this spoke on first start")
	bootstrapOut := fs.String("bootstrap-out", env("AGENTTRAP_BOOTSTRAP_OUT", ""), "where to write the bootstrap enrollment bundle")
	resolverURL := fs.String("resolver-url", env("AGENTTRAP_RESOLVER_URL", ""), "optional reverse-DNS resolver service")
	operators := fs.String("operators", env("AGENTTRAP_OPERATORS", ""), "comma-separated operator IPs/CIDRs (our own traffic)")
	geoDB := fs.String("geo-db", env("AGENTTRAP_GEO_DB", ""), "DB-IP Lite City MMDB for the attack map (empty = map disabled)")
	_ = fs.Parse(args)

	if *dsn == "" {
		return errors.New("hub: --db or AGENTTRAP_DB is required")
	}
	adminToken := os.Getenv("AGENTTRAP_ADMIN_TOKEN")
	if *adminTokenFile != "" {
		b, err := os.ReadFile(*adminTokenFile)
		if err != nil {
			return err
		}
		adminToken = strings.TrimSpace(string(b))
	}
	if *autoPKI {
		if _, err := os.Stat(filepath.Join(*pkiDir, pki.IntermediateCertFile)); errors.Is(err, os.ErrNotExist) {
			if err := pki.Init(*pkiDir); err != nil {
				return err
			}
			log.Warn("created CA; move the root key offline for production (README: Spoke↔hub PKI)", "dir", *pkiDir)
		}
	}
	issuer, err := pki.LoadIssuer(*pkiDir)
	if err != nil {
		return err
	}
	packRaw := personas.DemoGPU
	if *packPath != "" {
		if packRaw, err = os.ReadFile(*packPath); err != nil {
			return err
		}
	}

	var store *hub.PGStore
	for attempt := 1; ; attempt++ {
		store, err = hub.OpenPG(ctx, *dsn)
		if err == nil {
			break
		}
		if attempt == 30 {
			return fmt.Errorf("hub: database: %w", err)
		}
		log.Warn("database not ready; retrying", "err", err)
		time.Sleep(2 * time.Second)
	}
	defer store.Close()

	h, err := hub.New(hub.Config{
		HubURL:      *hubURL,
		ServerNames: splitList(*names),
		AdminToken:  adminToken,
		ResolverURL: *resolverURL,
		Operators:   splitList(*operators),
	}, store, issuer, packRaw, log)
	if err != nil {
		return err
	}
	if err := h.LoadOperators(ctx); err != nil {
		return err
	}
	// The attack map's geolocation database is an optional host-mounted file
	// (DB-IP Lite City). Without it the map is disabled; nothing else changes.
	if gdb, err := geo.Open(*geoDB); err != nil {
		log.Warn("attack map geolocation disabled", "err", err, "path", *geoDB)
	} else if gdb != nil {
		defer gdb.Close()
		h.SetGeo(gdb)
		log.Info("attack map geolocation enabled", "path", *geoDB)
	}
	if err := h.IndexCanaries(ctx); err != nil {
		return err
	}
	go h.RunEnrichment(ctx)
	// The link graph needs the Apache AGE extension; without it the hub runs
	// as before, minus graph links.
	if g, err := graph.Open(ctx, *dsn); err != nil {
		log.Warn("link graph disabled", "err", err)
	} else {
		defer g.Close()
		h.SetGraph(g)
		go h.RunGraph(ctx)
	}

	if *bootstrapSpoke != "" {
		if err := bootstrap(ctx, h, store, *bootstrapSpoke, *bootstrapOut, log); err != nil {
			return err
		}
	}

	spokeSrv := &http.Server{
		Addr:              *spokeListen,
		Handler:           h.SpokeHandler(),
		TLSConfig:         h.SpokeTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
	}
	adminSrv := &http.Server{Addr: *adminListen, Handler: h.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- spokeSrv.ListenAndServeTLS("", "") }()
	go func() { errc <- adminSrv.ListenAndServe() }()
	log.Info("hub running", "spoke_listen", *spokeListen, "admin_listen", *adminListen)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = spokeSrv.Shutdown(shutdown)
	_ = adminSrv.Shutdown(shutdown)
	return nil
}

// bootstrap creates the first spoke and writes its enrollment bundle, so a
// single-node deployment can start without manual steps.
func bootstrap(ctx context.Context, h *hub.Hub, store hub.Store, id, out string, log *slog.Logger) error {
	if out == "" {
		return errors.New("hub: --bootstrap-out is required with --bootstrap-spoke")
	}
	if _, err := store.GetSpoke(ctx, id); err == nil {
		log.Info("bootstrap spoke already exists", "spoke", id)
		return nil
	} else if !errors.Is(err, hub.ErrNotFound) {
		return err
	}
	b, err := h.CreateSpoke(ctx, id)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return err
	}
	log.Info("bootstrap spoke created", "spoke", id, "bundle", out)
	return nil
}

func runSpoke(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("spoke", flag.ExitOnError)
	dataDir := fs.String("data-dir", env("AGENTTRAP_DATA_DIR", "/var/lib/agenttrap/spoke"), "spoke state directory")
	bundle := fs.String("bundle", env("AGENTTRAP_BUNDLE", ""), "enrollment bundle (first start only)")
	listen := fs.String("listen", env("AGENTTRAP_LISTEN", ":8080"), "facade listener (edge proxy only)")
	sensorListen := fs.String("sensor-listen", env("AGENTTRAP_SENSOR_LISTEN", ""), "listener for JA4 sensor reports (empty = disabled)")
	sshListen := fs.String("ssh-listen", env("AGENTTRAP_SSH_LISTEN", ""), "SSH decoy listener (empty = disabled)")
	sshRelays := fs.String("ssh-relays", env("AGENTTRAP_SSH_RELAYS", ""), "comma-separated CIDRs allowed to send a PROXY header to the SSH listener")
	redisListen := fs.String("redis-listen", env("AGENTTRAP_REDIS_LISTEN", ""), "Redis decoy listener (empty = disabled)")
	redisRelays := fs.String("redis-relays", env("AGENTTRAP_REDIS_RELAYS", ""), "comma-separated CIDRs allowed to send a PROXY header to the Redis listener")
	pgListen := fs.String("postgres-listen", env("AGENTTRAP_POSTGRES_LISTEN", ""), "Postgres decoy listener (empty = disabled)")
	pgRelays := fs.String("postgres-relays", env("AGENTTRAP_POSTGRES_RELAYS", ""), "comma-separated CIDRs allowed to send a PROXY header to the Postgres listener")
	eventBurst := fs.Int("event-burst", envInt("AGENTTRAP_EVENT_BURST", 100), "events a single source may record before throttling (0 disables)")
	eventRefill := fs.Duration("event-refill", envDuration("AGENTTRAP_EVENT_REFILL", 2*time.Second), "time a source takes to earn back one event after its burst")
	baseDomain := fs.String("base-domain", env("AGENTTRAP_BASE_DOMAIN", ""), "override persona domain, e.g. demogpu.localhost")
	trusted := fs.String("trusted-proxies", env("AGENTTRAP_TRUSTED_PROXIES", ""), "comma-separated CIDRs allowed to set X-Real-IP")
	pseudoKeyFile := fs.String("pseudonymize-key-file", env("AGENTTRAP_PSEUDONYMIZE_KEY_FILE", ""), "if set, client IPs are replaced by a keyed hash")
	redirectHTTPS := fs.Bool("redirect-https", env("AGENTTRAP_REDIRECT_HTTPS", "") == "true", "301 plain-HTTP persona requests to HTTPS (after logging)")
	moduleSpec := fs.String("modules", env("AGENTTRAP_MODULES", "all"), `honeypot modules to enable: "all", "none" or a comma-separated list`)
	_ = fs.Parse(args)

	mods, err := builtin.Select(*moduleSpec)
	if err != nil {
		return fmt.Errorf("spoke: %w", err)
	}
	opts := demogpu.Options{BaseDomain: *baseDomain, RedirectHTTPS: *redirectHTTPS, Modules: mods}
	for _, c := range splitList(*trusted) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("spoke: trusted proxy %q: %w", c, err)
		}
		opts.TrustedProxies = append(opts.TrustedProxies, p)
	}
	if *pseudoKeyFile != "" {
		key, err := os.ReadFile(*pseudoKeyFile)
		if err != nil {
			return err
		}
		opts.PseudonymizeKey = key
	}
	cfg := spoke.Config{DataDir: *dataDir, BundlePath: *bundle, Listen: *listen,
		SensorListen: *sensorListen, SSHListen: *sshListen, RedisListen: *redisListen,
		PostgresListen: *pgListen,
		EventBurst:     *eventBurst, EventRefill: *eventRefill, Facade: opts}
	for _, c := range splitList(*sshRelays) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("spoke: ssh relay %q: %w", c, err)
		}
		cfg.SSHRelays = append(cfg.SSHRelays, p)
	}
	for _, c := range splitList(*redisRelays) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("spoke: redis relay %q: %w", c, err)
		}
		cfg.RedisRelays = append(cfg.RedisRelays, p)
	}
	for _, c := range splitList(*pgRelays) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("spoke: postgres relay %q: %w", c, err)
		}
		cfg.PostgresRelays = append(cfg.PostgresRelays, p)
	}
	return spoke.Run(ctx, cfg, log)
}

// runAdmin calls the hub admin API. The API listens on loopback inside the
// hub container, so operators run this via "docker compose exec hub".
func runAdmin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	base := fs.String("url", env("AGENTTRAP_ADMIN_URL", "http://127.0.0.1:9090"), "admin API base URL")
	tokenFile := fs.String("token-file", env("AGENTTRAP_ADMIN_TOKEN_FILE", ""), "file holding the admin bearer token")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 2 || (rest[0] != "get" && rest[0] != "post") {
		usage()
		return errors.New("admin: expected get|post PATH [JSON]")
	}
	token := os.Getenv("AGENTTRAP_ADMIN_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	var body io.Reader
	if len(rest) > 2 {
		body = strings.NewReader(rest[2])
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(rest[0]), *base+rest[1], body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("admin: %s", resp.Status)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// runJA4Sensor captures TLS ClientHellos in the edge proxy's network
// namespace and reports their JA4 fingerprints to the spoke.
func runJA4Sensor(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("ja4-sensor", flag.ExitOnError)
	portList := fs.String("ports", env("AGENTTRAP_JA4_PORTS", "443"), "comma-separated TLS ports to watch")
	report := fs.String("report", env("AGENTTRAP_JA4_REPORT", "http://spoke:8081/sensor/tls"), "spoke sensor endpoint")
	_ = fs.Parse(args)
	var ports []uint16
	for _, p := range splitList(*portList) {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return fmt.Errorf("ja4-sensor: port %q: %w", p, err)
		}
		ports = append(ports, uint16(n))
	}

	queue := make(chan ja4.Result, 1024)
	client := &http.Client{Timeout: 5 * time.Second}
	var dropped, reportErrors atomic.Uint64
	go func() {
		for res := range queue {
			body, _ := json.Marshal(res)
			resp, err := client.Post(*report, "application/json", bytes.NewReader(body))
			if err != nil {
				reportErrors.Add(1)
				log.Warn("reporting fingerprint failed", "err", err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				reportErrors.Add(1)
				log.Warn("spoke rejected fingerprint", "status", resp.Status)
			}
		}
	}()
	// The sensor shares the edge proxy's network namespace. If the proxy
	// restarts it gets a new namespace and this process is left in the old
	// one, which then has only a loopback interface. Exit so the container
	// restart policy re-attaches the sensor to the proxy's current namespace.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !hasExternalInterface() {
					cancel(errors.New("ja4-sensor: network namespace has no external interface (edge proxy restarted); exiting to re-attach"))
					return
				}
			}
		}
	}()

	log.Info("ja4 sensor running", "ports", ports, "report", *report)
	err := ja4.Sniff(ctx, ports, func(res ja4.Result) {
		select {
		case queue <- res:
		default:
			dropped.Add(1)
		}
	}, func(st ja4.Stats) {
		attrs := []any{"segments", st.Segments, "hellos_started", st.Started, "fingerprints", st.Completed,
			"parse_errors", st.ParseErrors, "expired", st.Expired, "oversize", st.Oversize,
			"out_of_order", st.OutOfOrder, "flows_full", st.FlowsFull,
			"queue_dropped", dropped.Load(), "report_errors", reportErrors.Load()}
		if len(st.LastFailure) > 0 {
			attrs = append(attrs, "last_failure_hex", hex.EncodeToString(st.LastFailure))
		}
		log.Info("ja4 sensor stats", attrs...)
	}, 5*time.Minute)
	close(queue)
	if cause := context.Cause(ctx); err == nil && cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return err
}

// runDigest builds the findings digest from the admin API and emails it, or
// prints it with --dry-run.
func runDigest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	adminURL := fs.String("admin-url", env("AGENTTRAP_ADMIN_URL", "http://10.90.0.5:9090"), "hub admin API")
	tokenFile := fs.String("token-file", env("AGENTTRAP_ADMIN_TOKEN_FILE", ""), "admin token file")
	hours := fs.Int("hours", 24, "window in hours")
	persona := fs.String("persona", "DemoGPU", "name used in the subject")
	dryRun := fs.Bool("dry-run", false, "print the digest instead of sending it")
	to := fs.String("to", env("DIGEST_TO", ""), "recipient")
	from := fs.String("from", env("DIGEST_FROM", ""), "sender (validated in Mailjet)")
	fromName := fs.String("from-name", env("DIGEST_FROM_NAME", "DemoGPU"), "sender display name")
	apiKey := fs.String("mailjet-api-key", env("DIGEST_MAILJET_API_KEY", ""), "Mailjet API key")
	secretFile := fs.String("mailjet-secret-file", env("DIGEST_MAILJET_SECRET_FILE", ""), "file holding the Mailjet secret key")
	_ = fs.Parse(args)

	token := os.Getenv("AGENTTRAP_ADMIN_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	report, err := digest.Build(ctx, &digest.Client{BaseURL: *adminURL, Token: token}, time.Duration(*hours)*time.Hour)
	if err != nil {
		return err
	}
	report.Persona = *persona
	subject := report.Subject(*persona)
	text := report.Text()
	if *dryRun {
		fmt.Printf("Subject: %s\n\n%s", subject, text)
		return nil
	}
	if *to == "" || *from == "" {
		return errors.New("digest: --to and --from are required (or use --dry-run)")
	}
	m := digest.Mail{APIKey: *apiKey, From: *from, FromName: *fromName, To: *to}
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			return err
		}
		m.SecretKey = strings.TrimSpace(string(b))
	}
	return m.Send(subject, text, report.HTML())
}

// runNotify mails an alert when events stop reaching the hub (and when they
// resume), then forwards new contact form messages by email. At most 10 are sent
// individually per run; the rest go out as one summary, so form spam cannot
// flood the mailbox.
func runNotify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("notify", flag.ExitOnError)
	adminURL := fs.String("admin-url", env("AGENTTRAP_ADMIN_URL", "http://10.90.0.5:9090"), "hub admin API")
	tokenFile := fs.String("token-file", env("AGENTTRAP_ADMIN_TOKEN_FILE", ""), "admin token file")
	state := fs.String("state", env("NOTIFY_STATE", "/state/notify.json"), "file remembering forwarded messages")
	persona := fs.String("persona", "DemoGPU", "name used in subjects")
	to := fs.String("to", env("DIGEST_TO", ""), "recipient")
	from := fs.String("from", env("DIGEST_FROM", ""), "sender (validated in Mailjet)")
	fromName := fs.String("from-name", env("DIGEST_FROM_NAME", "DemoGPU"), "sender display name")
	apiKey := fs.String("mailjet-api-key", env("DIGEST_MAILJET_API_KEY", ""), "Mailjet API key")
	secretFile := fs.String("mailjet-secret-file", env("DIGEST_MAILJET_SECRET_FILE", ""), "Mailjet secret key file")
	_ = fs.Parse(args)
	token := os.Getenv("AGENTTRAP_ADMIN_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	base := digest.Mail{APIKey: *apiKey, From: *from, FromName: *fromName, To: *to}
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			return err
		}
		base.SecretKey = strings.TrimSpace(string(b))
	}
	client := &digest.Client{BaseURL: *adminURL, Token: token}

	// Ingestion first: a stalled pipeline matters more than any one message,
	// and the check must run even when there is nothing to forward.
	alertState := filepath.Join(filepath.Dir(*state), "ingest-alert.json")
	if alert, err := digest.IngestAlert(ctx, client, *persona, alertState, time.Now()); err != nil {
		return err
	} else if alert != nil {
		if err := base.Send(alert.Subject, alert.Text, alert.HTML); err != nil {
			return err
		}
		if err := alert.Commit(); err != nil {
			return err
		}
	}

	subs, st, err := digest.NewSubmissions(ctx, client, *state)
	if err != nil || len(subs) == 0 {
		return err
	}
	var sent []string
	const maxIndividual = 10
	for i, sub := range subs {
		if i == maxIndividual {
			break
		}
		m := base
		m.ReplyTo = digest.ValidReplyTo(sub.ReplyTo)
		subject, text, htmlBody := digest.SubmissionMail(*persona, sub)
		if err := m.Send(subject, text, htmlBody); err != nil {
			_ = st.MarkSent(sent, *state)
			return err
		}
		sent = append(sent, sub.ID)
	}
	if rest := subs[min(len(subs), maxIndividual):]; len(rest) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d more contact form messages (not sent individually):\n\n", len(rest))
		for _, sub := range rest {
			fmt.Fprintf(&b, "- %s %s <%s>: %.200s\n", sub.Time.UTC().Format("2006-01-02 15:04"), sub.Name, sub.ReplyTo, sub.Message)
			sent = append(sent, sub.ID)
		}
		if err := base.Send(fmt.Sprintf("[%s contact] %d more messages", *persona, len(rest)), b.String(),
			"<pre>"+html.EscapeString(b.String())+"</pre>"); err != nil {
			return err
		}
	}
	return st.MarkSent(sent, *state)
}

// runExport writes a dated snapshot of the exports from the admin API.
func runExport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	adminURL := fs.String("admin-url", env("AGENTTRAP_ADMIN_URL", "http://10.90.0.5:9090"), "hub admin API")
	tokenFile := fs.String("token-file", env("AGENTTRAP_ADMIN_TOKEN_FILE", ""), "admin token file")
	out := fs.String("out", env("EXPORT_DIR", "/exports"), "output directory (a dated subdirectory is created)")
	hours := fs.Int("hours", 24, "window in hours")
	_ = fs.Parse(args)
	token := os.Getenv("AGENTTRAP_ADMIN_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	dir := filepath.Join(*out, time.Now().UTC().Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"actors.jsonl", "sessions.jsonl", "campaigns.jsonl", "iocs.stix.json", "dnsbl.zone", "blocklist.csv", "events.jsonl"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/admin/export/%s?hours=%d", *adminURL, name, *hours), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("export %s: %s", name, resp.Status)
		}
		path := filepath.Join(dir, name)
		var w io.WriteCloser
		f, err := os.Create(path + ".tmp")
		if err != nil {
			resp.Body.Close()
			return err
		}
		w = f
		if name == "events.jsonl" {
			w = gzip.NewWriter(f)
			path += ".gz"
		}
		_, err = io.Copy(w, resp.Body)
		resp.Body.Close()
		if w != io.WriteCloser(f) {
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if err := os.Rename(f.Name(), path); err != nil {
			return err
		}
	}
	fmt.Println("export written to", dir)
	return nil
}

// runRelay forwards a published port to a decoy on an internal network.
func runRelay(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	listen := fs.String("listen", env("AGENTTRAP_RELAY_LISTEN", ":22"), "public listener")
	backend := fs.String("backend", env("AGENTTRAP_RELAY_BACKEND", "spoke:2022"), "internal backend address")
	burst := fs.Int("rate-burst", envInt("AGENTTRAP_RELAY_RATE_BURST", 15), "connections a source may open before throttling (0 disables)")
	refill := fs.Duration("rate-refill", envDuration("AGENTTRAP_RELAY_RATE_REFILL", time.Minute), "time to earn back one connection after the burst")
	exempt := fs.String("exempt", env("AGENTTRAP_RELAY_EXEMPT", ""), "comma-separated CIDRs never rate-limited (operators, health checks)")
	_ = fs.Parse(args)
	cfg := relay.Config{Listen: *listen, Backend: *backend, Burst: *burst, Refill: *refill}
	for _, c := range splitList(*exempt) {
		p, err := parsePrefixOrAddr(c)
		if err != nil {
			return fmt.Errorf("relay: exempt %q: %w", c, err)
		}
		cfg.Exempt = append(cfg.Exempt, p)
	}
	return relay.Run(ctx, cfg, log)
}

// runTestSuite runs the facade test suite against a persona and exits
// non-zero below the gate. It creates events on the target: run it from an
// operator address.
func runTestSuite(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("testsuite", flag.ExitOnError)
	domain := fs.String("domain", "demogpu.example", "persona apex domain")
	addr := fs.String("addr", "", "connect every hostname to this host:port instead of DNS (local deployment)")
	scheme := fs.String("scheme", "https", "https or http")
	insecure := fs.Bool("insecure", false, "accept any TLS certificate (self-signed dev certificate)")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	_ = fs.Parse(args)
	rep := testsuite.Run(ctx, testsuite.Target{Domain: *domain, Scheme: *scheme, Addr: *addr, Insecure: *insecure})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		for _, c := range rep.Checks {
			mark := "PASS"
			switch {
			case c.Skipped:
				mark = "skip"
			case !c.Pass:
				mark = "FAIL"
			}
			line := fmt.Sprintf("%-4s %-9s %s", mark, c.Dimension, c.Title)
			if (!c.Pass || c.Skipped) && c.Detail != "" {
				line += "  (" + c.Detail + ")"
			}
			fmt.Println(line)
		}
		fmt.Println()
		for _, d := range rep.Dimensions {
			fmt.Printf("%-9s %4.1f / %2.0f  (%d/%d checks)\n", d.Name, d.Score, d.Weight, d.Passed, d.Checked)
		}
		fmt.Printf("\nconsistency score %.1f / 100 (gate %.0f): %s\n", rep.Score, rep.Gate, map[bool]string{true: "pass", false: "FAIL"}[rep.Pass])
	}
	if !rep.Pass {
		os.Exit(1)
	}
	return nil
}

// runResolver answers reverse-DNS verification queries from the hub. It is
// the only component with DNS access; it accepts nothing but an IP address.
func runResolver(ctx context.Context, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("resolver", flag.ExitOnError)
	listen := fs.String("listen", env("AGENTTRAP_RESOLVER_LISTEN", ":8053"), "listener (private network shared with the hub only)")
	_ = fs.Parse(args)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/verify", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if _, err := netip.ParseAddr(ip); err != nil {
			http.Error(w, "ip required", http.StatusBadRequest)
			return
		}
		lctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		res, err := rdns.Lookup(lctx, net.DefaultResolver, ip)
		if err != nil {
			http.Error(w, "lookup failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Info("resolver running", "listen", *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hasExternalInterface reports whether the current network namespace has any
// interface that is up and is not loopback.
func hasExternalInterface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return true // don't restart on a transient error
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback == 0 && ifc.Flags&net.FlagUp != 0 {
			return true
		}
	}
	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(name); ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			return d
		}
	}
	return def
}

// parsePrefixOrAddr accepts a CIDR or a bare IP (treated as a single-host
// prefix), so lists like AGENTTRAP_OPERATORS can hold either.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
