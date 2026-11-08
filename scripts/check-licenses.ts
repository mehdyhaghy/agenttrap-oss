// Fails unless every JavaScript and Go dependency is under a permissive
// license (MIT, Apache-2.0, BSD, ISC and similar). Copyleft (GPL, LGPL, AGPL,
// MPL, EPL, ...) and unknown licenses fail. Run: bun scripts/check-licenses.ts
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const allowed = new Set(['MIT', 'MIT-0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'Apache-2.0',
  'BlueOak-1.0.0', 'CC0-1.0', 'Unlicense', 'Python-2.0', 'Zlib', 'CC-BY-4.0'])

// Build-only tools that may be MPL-2.0 (weak, file-level copyleft). They run
// only while building, are never modified and never ship: the final image holds
// the Go binary and the built assets, which are not covered by their license.
// List each by name with its reason; shipped dependencies stay permissive.
const buildOnlyMPL: Record<string, string> = {
  lightningcss: 'Vite 8 CSS minifier, build stage only',
}
function buildOnlyAllowed(name: string | undefined, lic: string): boolean {
  if (!name || lic !== 'MPL-2.0') return false
  return Object.keys(buildOnlyMPL).some((n) => name === n || name.startsWith(n + '-')) // platform binaries
}

// Evaluates simple SPDX expressions: "A OR B" passes if any part passes,
// "A AND B" only if all do.
function permissive(expr: string): boolean {
  const e = expr.replace(/[()]/g, ' ').trim()
  if (/ OR /i.test(e)) return e.split(/ OR /i).some((p) => permissive(p))
  if (/ AND /i.test(e)) return e.split(/ AND /i).every((p) => permissive(p))
  return allowed.has(e.trim())
}

const failures: string[] = []
const buildOnly = new Set<string>()
let checked = 0

function scanNodeModules(root: string): void {
  if (!existsSync(root)) return
  const visit = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      if (name.startsWith('.')) continue
      const p = join(dir, name)
      if (name.startsWith('@')) { visit(p); continue }
      const pkgFile = join(p, 'package.json')
      if (!existsSync(pkgFile)) continue
      const pkg = JSON.parse(readFileSync(pkgFile, 'utf8')) as { name?: string; version?: string; license?: unknown; licenses?: { type?: string }[] }
      let lic = typeof pkg.license === 'string' ? pkg.license : (pkg.license as { type?: string } | undefined)?.type ?? ''
      if (!lic && Array.isArray(pkg.licenses)) lic = pkg.licenses.map((l) => l.type ?? '').join(' OR ')
      checked++
      if (!permissive(lic) && buildOnlyAllowed(pkg.name, lic)) buildOnly.add(pkg.name!)
      else if (!permissive(lic)) failures.push(`npm ${pkg.name}@${pkg.version} (${root}): ${lic || 'no license field'}`)
      const nested = join(p, 'node_modules')
      if (existsSync(nested) && statSync(nested).isDirectory()) visit(nested)
    }
  }
  visit(root)
}

for (const dir of ['web/node_modules', 'site/node_modules']) scanNodeModules(dir)

// Go modules: classify each module's license file by its text.
const mods = spawnSync('go', ['list', '-m', '-f', '{{.Path}}\t{{.Dir}}\t{{.Main}}', 'all'], { encoding: 'utf8' })
for (const line of mods.stdout.trim().split('\n')) {
  const [path, dir, main] = line.split('\t')
  if (!path || main === 'true' || !dir) continue
  checked++
  const file = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'LICENCE'].map((f) => join(dir, f)).find((f) => existsSync(f))
  if (!file) { failures.push(`go ${path}: no license file`); continue }
  const text = readFileSync(file, 'utf8')
  const ok = /Permission is hereby granted, free of charge/.test(text) || // MIT
    /Redistribution and use in source and binary forms/.test(text) || // BSD
    /Apache License[\s\S]*Version 2\.0/.test(text) || // Apache-2.0
    /Permission to use, copy, modify, and\/or distribute this software/.test(text) // ISC
  const copyleft = /GNU (Affero |Lesser )?General Public License|Mozilla Public License|Eclipse Public License/.test(text)
  if (!ok || copyleft) failures.push(`go ${path}: not recognised as permissive (${file})`)
}

if (failures.length) {
  console.error(`License check FAILED (${failures.length} of ${checked}):\n  ` + failures.join('\n  '))
  process.exit(1)
}
const note = buildOnly.size ? ` (build-only MPL-2.0 allowed: ${[...buildOnly].sort().join(', ')})` : ''
console.log(`License check passed: ${checked} dependencies, all permissive${note}.`)
