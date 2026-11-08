// Package modules defines honeypot modules: self-contained traps that each
// answer one kind of attack, independent of the persona. The facade offers
// every HTTP request to the enabled modules before persona routing; the module
// with the strongest claim answers it and reports what it saw, and the facade
// records that as events (a request event tagged with the module, plus an
// exploit event when the request was an attack on a known vulnerability).
//
// Adding a module: create modules/<name> implementing Module, keep everything
// it needs (signatures, fake responses, version strings) inside it, register
// it in modules/builtin, and add tests next to it. A module never records
// events or touches the persona itself; it only returns a Hit.
package modules

import "net/http"

// Claim is how strongly a module wants a request. The facade picks the
// strongest; ties go to the module listed first.
type Claim int

const (
	// Pass leaves the request to other modules and the persona.
	Pass Claim = iota
	// Vhost serves a request for a hostname no persona surface answers
	// (a bare IP, an unknown name): the module plays the default virtual host.
	Vhost
	// Attack recognizes the request as this module's attack, on any host.
	Attack
)

// Stages of an attack a Hit reports.
const (
	StageProbe   = "probe"   // looked for a vulnerable target (version, info page)
	StageExploit = "exploit" // sent an exploit payload
)

// Request is what the facade knows about a request before a module sees it.
type Request struct {
	*http.Request
	// Surface is the persona surface the Host header names, or "" when no
	// surface does (the default virtual host).
	Surface string
	// Reveal, when set, mints a per-exposure canary for a persona canary slot
	// (e.g. "aws_access_key_id", "provider_key_vllm") and records that it was
	// shown to this client; a later use of the value anywhere names this exact
	// exposure. It returns "" for a slot the persona does not have.
	Reveal func(slot string) string
}

// Canary returns a canary for slot, or fallback when the persona has none
// (or no persona is attached, as in a module's own tests).
func (r Request) Canary(slot, fallback string) string {
	if r.Reveal != nil {
		if v := r.Reveal(slot); v != "" {
			return v
		}
	}
	return fallback
}

// Module is one honeypot trap.
type Module interface {
	// Name is the stable identifier recorded in events and used in config.
	Name() string
	// Claim inspects the request line and headers, never the body. It runs
	// on every request, so it must be cheap.
	Claim(r Request) Claim
	// Serve answers a claimed request. It owns the body: it reads what it
	// needs and discards the rest.
	Serve(w http.ResponseWriter, r Request) Hit
}

// Hit is what a module saw while serving a request.
type Hit struct {
	// Attack names the attack in words, e.g. "PHP2Shell".
	Attack string
	// CVE lists the vulnerabilities targeted, when known.
	CVE []string
	// Stage is StageProbe, StageExploit, or "" for an ordinary request to
	// the trap. Only probes and exploits produce an exploit event.
	Stage string
	// Signals are the short names of the indicators that matched.
	Signals []string
	// Detail is recorded as-is on the events; keep values small.
	Detail map[string]any
}

// Pick returns the module with the strongest claim on r, or nil.
func Pick(mods []Module, r Request) Module {
	var best Module
	bestClaim := Pass
	for _, m := range mods {
		if c := m.Claim(r); c > bestClaim {
			best, bestClaim = m, c
		}
	}
	return best
}
