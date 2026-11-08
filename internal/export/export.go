// Package export writes classified actors and events in formats for
// analytics and threat-intelligence sharing: STIX 2.1, an rbldnsd DNSBL zone,
// CSV and JSON Lines. Operator traffic must be excluded by the caller.
package export

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"agenttrap/internal/classify"
)

// Listed reports whether an actor belongs in shared indicator feeds, and
// with which DNSBL return code. Verified crawlers, browsers, unknown and
// low-confidence actors are never listed.
func Listed(a classify.Actor) (code string, label string, ok bool) {
	switch {
	case a.Class == classify.RogueAgent:
		return "127.0.0.3", "rogue agent", true
	case a.CrawlerCheck == "impersonation":
		return "127.0.0.4", "crawler impersonation", true
	case a.Class == classify.Scanner && a.Confidence != "low":
		return "127.0.0.2", "scanner", true
	}
	return "", "", false
}

func confidence(a classify.Actor) int {
	switch a.Confidence {
	case "high":
		return 85
	case "medium":
		return 60
	}
	return 30
}

// uuid5 derives a stable UUIDv5 so the same indicator keeps its STIX id
// across exports.
func uuid5(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.Sum(append(ns, []byte(name)...))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	x := hex.EncodeToString(h[:16])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// STIX writes a STIX 2.1 bundle: the producing identity and one indicator
// per listed address.
func STIX(w io.Writer, producer string, actors []classify.Actor, now time.Time) error {
	ts := now.UTC().Format("2006-01-02T15:04:05.000Z")
	ident := "identity--" + uuid5("identity:"+producer)
	objects := []map[string]any{{
		"type": "identity", "spec_version": "2.1", "id": ident, "created": ts, "modified": ts,
		"name": producer, "identity_class": "system",
	}}
	for _, a := range actors {
		_, label, ok := Listed(a)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(a.Source)
		if err != nil {
			continue // pseudonymized sources are not shareable indicators
		}
		kind := "ipv4-addr"
		if addr.Is6() && !addr.Is4In6() {
			kind = "ipv6-addr"
		}
		itype := "anomalous-activity"
		if a.Class == classify.RogueAgent || a.CrawlerCheck == "impersonation" {
			itype = "malicious-activity"
		}
		ind := map[string]any{
			"type": "indicator", "spec_version": "2.1",
			"id":      "indicator--" + uuid5("indicator:"+a.Source+":"+a.Class),
			"created": ts, "modified": ts,
			"created_by_ref":  ident,
			"name":            label + " " + a.Source,
			"description":     strings.Join(a.Reasons, "; "),
			"indicator_types": []string{itype},
			"pattern":         fmt.Sprintf("[%s:value = '%s']", kind, addr.Unmap()),
			"pattern_type":    "stix",
			"valid_from":      a.FirstSeen.UTC().Format("2006-01-02T15:04:05.000Z"),
			"valid_until":     a.LastSeen.UTC().Add(30 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
			"confidence":      confidence(a),
			"labels":          []string{a.Class, strings.ReplaceAll(label, " ", "-")},
			"x_user_agents":   a.UserAgents,
			"x_ja4":           a.JA4,
			"x_ja3":           a.JA3,
			"x_network":       a.Network,
			"x_hostname":      a.Hostname,
			"x_requests":      a.Features.Requests,
		}
		if a.Identity != nil {
			ind["x_declared_identity"] = a.Identity
		}
		objects = append(objects, ind)
	}
	return json.NewEncoder(w).Encode(map[string]any{
		"type": "bundle", "id": "bundle--" + uuid5("bundle:"+producer+":"+ts), "objects": objects,
	})
}

// DNSBL writes an rbldnsd ip4set zone. Return codes: 127.0.0.2 scanner,
// 127.0.0.3 rogue agent, 127.0.0.4 crawler impersonation. IPv6 addresses go
// to a separate ip6tset data file (see DNSBL6).
func DNSBL(w io.Writer, zone string, actors []classify.Actor, now time.Time) error {
	fmt.Fprintf(w, "$SOA 3600 ns.%s hostmaster.%s %d 3600 600 604800 300\n", zone, zone, now.Unix())
	fmt.Fprintf(w, "$NS 3600 ns.%s\n", zone)
	fmt.Fprintf(w, ":127.0.0.2:Listed by %s: $\n", zone)
	for _, a := range actors {
		code, label, ok := Listed(a)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(a.Source)
		if err != nil || (addr.Is6() && !addr.Is4In6()) {
			continue
		}
		fmt.Fprintf(w, "%s :%s:%s\n", addr.Unmap(), code, label)
	}
	return nil
}

// CSV writes one row per listed address.
func CSV(w io.Writer, actors []classify.Actor) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip", "class", "listing", "confidence", "first_seen", "last_seen", "requests",
		"declared_name", "declared_version", "declared_contact", "network", "hostname", "ja4", "user_agent", "reasons", "ja3"})
	for _, a := range actors {
		_, label, ok := Listed(a)
		if !ok {
			continue
		}
		var name, ver, contact string
		if a.Identity != nil {
			name, ver = a.Identity.Name, a.Identity.Version
			contact = a.Identity.URL
			if contact == "" {
				contact = a.Identity.Email
			}
		}
		ua := ""
		if len(a.UserAgents) > 0 {
			ua = a.UserAgents[0]
		}
		row := []string{a.Source, a.Class, label, a.Confidence, a.FirstSeen.UTC().Format(time.RFC3339),
			a.LastSeen.UTC().Format(time.RFC3339), fmt.Sprint(a.Features.Requests), name, ver, contact,
			a.Network, a.Hostname, strings.Join(a.JA4, " "), ua, strings.Join(a.Reasons, "; "), strings.Join(a.JA3, " ")}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe keeps attacker-chosen text (User-Agent, agent name, contact) from
// running as a formula when the CSV is opened in a spreadsheet.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// JSONL writes each value as one JSON line.
func JSONL[T any](w io.Writer, rows []T) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
