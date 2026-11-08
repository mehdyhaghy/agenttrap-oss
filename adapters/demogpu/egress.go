package demogpu

// The controlled egress broker: the single chokepoint for an outbound request
// an occupant of the honeypot makes to the outside world (spec §10, §15).
// Nothing is ever forwarded. The broker records the destination and payload and
// flags any canary in it as exfiltration, then returns a contained decision:
// a plausible success for a recognised collector (so the occupant believes the
// exfil worked and reveals its full chain), or, by default, a refusal the way
// an egress-firewalled host drops the connection. Internal and persona-owned
// destinations are lateral movement, not egress, and do not pass through here.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"agenttrap/internal/events"
)

type egressReq struct {
	Via    string // origin surface, e.g. "ssh"
	Tool   string // "curl", "wget"
	Method string
	URL    string
	Host   string // destination host[:port]
	Body   string // request payload (already expanded); may hold exfil data
}

type egressAction string

const (
	egressSimulate egressAction = "simulate"
	egressDeny     egressAction = "deny"
)

type egressResult struct {
	Action egressAction
	Body   string // simulated response body, for the tool to print
}

// collectorHosts are destinations that exist to receive data; outbound to one
// is drawn out with a simulated success. Everything else defaults to deny.
var collectorHosts = []string{
	"webhook.site", "requestbin", "pipedream.net", "ngrok.", "ngrok-free.",
	"pastebin.com", "hastebin", "paste.ee", "dpaste.", "transfer.sh", "0x0.st", "file.io",
	"discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com",
	"api.telegram.org", "oast.", "interact.sh", "burpcollaborator", "dnslog", "requestcatcher.com",
}

// egress records an outbound attempt, flags any canary in it as exfiltration,
// and returns the contained decision.
func (s *Server) egress(r *http.Request, req egressReq) egressResult {
	found := s.canaries.Scan(req.URL + "\n" + req.Body)
	dataCarrying := req.Body != "" || !(req.Method == "" || req.Method == "GET" || req.Method == "HEAD")
	action := egressDeny
	if matchesCollector(req.URL, req.Host) {
		action = egressSimulate
	}

	detail := map[string]any{"op": "egress", "via": req.Via, "tool": req.Tool,
		"method": defaultStr(req.Method, "GET"), "host": truncate(egressHostname(req.Host), 255),
		"url": truncate(req.URL, 500), "action": string(action), "data_carrying": dataCarrying}
	if req.Body != "" {
		sum := sha256.Sum256([]byte(req.Body))
		detail["body_sha256"] = hex.EncodeToString(sum[:])
		detail["body_bytes"] = len(req.Body)
		detail["body"] = truncate(strings.ToValidUTF8(req.Body, "�"), maxBodyCapture)
	}
	if len(found) > 0 {
		slots := make([]string, 0, len(found))
		for _, f := range found {
			slots = append(slots, f.Slot)
		}
		detail["exfil_slots"] = slots
	}
	s.emit(r, events.Event{Kind: events.KindToolCall, Detail: detail})

	// A canary in the payload is exfiltration: record each as an outbound use,
	// tagged with the destination so it is not confused with a use against us.
	for _, f := range found {
		s.emit(r, events.Event{Kind: events.KindCanaryUsed, CanarySlot: f.Slot, Detail: map[string]any{
			"exfil": true, "direction": "outbound", "channel": req.Via, "tool": req.Tool,
			"destination": truncate(egressHostname(req.Host), 255), "url": truncate(req.URL, 500),
			"exposure_id": f.ExposureID}})
		s.noteDepth(infoFrom(r.Context()).source, "used", f.Slot)
	}
	return egressResult{Action: action, Body: simulatedBody(req)}
}

func matchesCollector(url, host string) bool {
	u, h := strings.ToLower(url), egressHostname(host)
	for _, c := range collectorHosts {
		if strings.Contains(h, c) || strings.Contains(u, c) {
			return true
		}
	}
	return false
}

// simulatedBody returns a plausible success body for a simulated collector.
func simulatedBody(req egressReq) string {
	switch h := egressHostname(req.Host); {
	case strings.Contains(h, "api.telegram.org"):
		return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d}}`, 100+len(req.Body)%900) + "\n"
	case strings.Contains(h, "hooks.slack.com"):
		return "ok"
	default:
		return "" // most collectors return an empty 200 (Discord returns 204)
	}
}

// isInternalHost reports whether host is inside the synthetic enterprise (the
// persona's own names, or a private/loopback/link-local address). Reaching one
// is lateral movement, handled elsewhere, not egress.
func (s *Server) isInternalHost(host string) bool {
	h := egressHostname(host)
	if h == "localhost" || h == s.domain || strings.HasSuffix(h, "."+s.domain) || strings.HasSuffix(h, ".internal") {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}

func egressHostname(host string) string {
	if strings.HasPrefix(host, "[") { // [ipv6]:port
		if i := strings.IndexByte(host, ']'); i > 0 {
			return strings.ToLower(host[1:i])
		}
	}
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	return strings.ToLower(host)
}
