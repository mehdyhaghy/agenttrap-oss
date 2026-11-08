// Package personas embeds the frozen world packs shipped with the binary.
package personas

import _ "embed"

// DemoGPU is the v1 facade persona.
//
//go:embed demogpu/pack.json
var DemoGPU []byte
