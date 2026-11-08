// Package rdns verifies self-declared crawlers with forward-confirmed reverse
// DNS: the address must resolve to a hostname in the operator's domain, and
// that hostname must resolve back to the same address.
package rdns

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Family is a crawler operator that documents reverse-DNS verification.
type Family struct {
	Name    string
	UA      *regexp.Regexp
	Domains []string // hostname must end with one of these
}

// Families with a documented reverse-DNS convention. Crawlers that publish IP
// ranges instead (for example GPTBot or ClaudeBot) are not listed and are
// reported as unverifiable.
var Families = []Family{
	{"Google", regexp.MustCompile(`(?i)googlebot|google-inspectiontool|googleother|adsbot-google|mediapartners-google|google-extended|storebot-google`), []string{".googlebot.com", ".google.com", ".googleusercontent.com"}},
	{"Bing", regexp.MustCompile(`(?i)bingbot|msnbot|adidxbot|bingpreview`), []string{".search.msn.com"}},
	{"Apple", regexp.MustCompile(`(?i)applebot`), []string{".applebot.apple.com"}},
	{"Yandex", regexp.MustCompile(`(?i)yandex(bot|images|mobilebot)`), []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
	{"Baidu", regexp.MustCompile(`(?i)baiduspider`), []string{".baidu.com", ".baidu.jp"}},
	{"Amazon", regexp.MustCompile(`(?i)amazonbot`), []string{".crawl.amazonbot.amazon"}},
}

// Claimed returns the family a user agent claims, if it is one we can verify.
func Claimed(ua string) (Family, bool) {
	for _, f := range Families {
		if f.UA.MatchString(ua) {
			return f, true
		}
	}
	return Family{}, false
}

// Result of verifying one address.
type Result struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	// Confirmed lists hostnames that resolve back to IP.
	Confirmed []string `json:"confirmed"`
}

// Lookup performs reverse DNS and forward confirmation for ip.
func Lookup(ctx context.Context, r *net.Resolver, ip string) (Result, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Result{}, err
	}
	res := Result{IP: addr.String()}
	names, err := r.LookupAddr(ctx, addr.String())
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return res, nil
		}
		return res, err
	}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		res.Hostnames = append(res.Hostnames, n)
		addrs, err := r.LookupNetIP(ctx, "ip", n)
		if err != nil {
			continue
		}
		if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == addr.Unmap() }) {
			res.Confirmed = append(res.Confirmed, n)
		}
	}
	return res, nil
}

// Verified reports whether res proves the address belongs to family.
func Verified(res Result, family Family) (string, bool) {
	for _, h := range res.Confirmed {
		for _, d := range family.Domains {
			if strings.HasSuffix("."+h, d) {
				return h, true
			}
		}
	}
	return "", false
}

// networks maps hostname suffixes to a readable network name. It is a hint
// for the dashboard (cloud host vs. home connection), not proof.
var networks = []struct{ suffix, name string }{
	{".amazonaws.com", "AWS"}, {".googleusercontent.com", "Google Cloud"}, {".googlebot.com", "Google (crawler)"},
	{".1e100.net", "Google"}, {".cloudapp.net", "Azure"}, {".cloudapp.azure.com", "Azure"},
	{".search.msn.com", "Microsoft (Bing)"}, {".linodeusercontent.com", "Akamai/Linode"}, {".members.linode.com", "Akamai/Linode"},
	{".your-server.de", "Hetzner"}, {".hetzner.com", "Hetzner"}, {".clients.your-server.de", "Hetzner"},
	{".ovh.net", "OVH"}, {".ovh.ca", "OVH"}, {".ip-54-38.eu", "OVH"}, {".contaboserver.net", "Contabo"},
	{".vultrusercontent.com", "Vultr"}, {".choopa.net", "Vultr"}, {".leaseweb.net", "Leaseweb"},
	{".scaleway.com", "Scaleway"}, {".poneytelecom.eu", "Scaleway"}, {".applebot.apple.com", "Apple (crawler)"},
	{".crawl.yandex.net", "Yandex (crawler)"}, {".crawl.baidu.com", "Baidu (crawler)"}, {".crawl.amazonbot.amazon", "Amazon (crawler)"},
	{".comcast.net", "Comcast (residential)"}, {".verizon.net", "Verizon (residential)"}, {".rr.com", "Charter (residential)"},
	{".charter.com", "Charter (residential)"}, {".cox.net", "Cox (residential)"}, {".sbcglobal.net", "AT&T (residential)"},
	{".att.net", "AT&T (residential)"}, {".btcentralplus.com", "BT (residential)"}, {".virginm.net", "Virgin Media (residential)"},
	{".t-ipconnect.de", "Deutsche Telekom (residential)"}, {".telus.net", "Telus (residential)"}, {".shawcable.net", "Shaw (residential)"},
	{".bell.ca", "Bell (residential)"}, {".wanadoo.fr", "Orange (residential)"}, {".orange.fr", "Orange (residential)"},
}

// Network returns a readable network name for a hostname, falling back to
// its last two labels.
func Network(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	for _, n := range networks {
		if strings.HasSuffix("."+host, n.suffix) {
			return n.name
		}
	}
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
}
