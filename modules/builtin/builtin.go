// Package builtin lists the honeypot modules compiled into AgentTrap.
package builtin

import (
	"fmt"
	"strings"

	"agenttrap/modules"
	"agenttrap/modules/aiplatforms"
	"agenttrap/modules/php2shell"
	"agenttrap/modules/secretfiles"
	"agenttrap/modules/traversal"
	"agenttrap/modules/webshell"
)

// All returns every built-in module in claim-priority order: on equal
// claims the earlier module wins, so the most specific traps come first
// (a traversal to /.env is a traversal; a webshell POST with a session cookie
// is a webshell, not PHP2Shell), and php2shell, which also plays the default
// virtual host, comes last.
func All() []modules.Module {
	return []modules.Module{
		traversal.New(),
		webshell.New(),
		aiplatforms.New(),
		secretfiles.New(),
		php2shell.New(),
	}
}

// Select returns the modules named in spec: "all" (or empty) for every
// module, "none" for no module, otherwise a comma-separated list of names.
func Select(spec string) ([]modules.Module, error) {
	spec = strings.TrimSpace(spec)
	switch spec {
	case "", "all":
		return All(), nil
	case "none":
		return nil, nil
	}
	byName := map[string]modules.Module{}
	for _, m := range All() {
		byName[m.Name()] = m
	}
	var out []modules.Module
	for _, name := range strings.Split(spec, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		m, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown module %q", name)
		}
		out = append(out, m)
	}
	return out, nil
}
