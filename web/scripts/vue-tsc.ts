// Runs vue-tsc on the Bun runtime.
//
// vue-tsc (via @volar/typescript) adds .vue support by swapping fs.readFileSync
// while it require()s TypeScript's tsc.js, so Node's loader reads a patched
// copy. Bun's module loader does not read files through fs.readFileSync, so
// the patch never applies and every .vue import fails with TS2307.
//
// This wrapper performs Volar's own transformation explicitly, writes the
// patched compiler next to the original (so its relative requires resolve),
// and loads that file. Everything else is stock vue-tsc. Remove it once the
// toolchain moves to TypeScript 7.1 with native vue-tsc support.
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

interface RunTscOptions {
  extraSupportedExtensions: string[]
  extraExtensionsToRemove: string[]
}
interface VolarRunTsc {
  runTsc: (tscPath: string, options: string[] | RunTscOptions, getLanguagePlugins: unknown) => unknown
  getLanguagePlugins: unknown
  transformTscContent: (tsc: string, proxyApiPath: string, extra: string[], remove: string[], getLanguagePluginsFile: string) => string
}

const volarPath = require.resolve('@volar/typescript/lib/quickstart/runTsc')
const proxyApiPath = require.resolve('@volar/typescript/lib/node/proxyCreateProgram')
const volar = require(volarPath) as VolarRunTsc
const vueTsc = require('vue-tsc') as { run: () => void }

volar.runTsc = (tscPath, options, getLanguagePlugins) => {
  // The patched compiler looks the plugins up on Volar's module exports.
  volar.getLanguagePlugins = getLanguagePlugins
  const extra = Array.isArray(options) ? options : options.extraSupportedExtensions
  const remove = Array.isArray(options) ? [] : options.extraExtensionsToRemove

  // TypeScript >= 5.7 ships tsc.js as a shim around the real compiler module.
  let file = tscPath
  let source = fs.readFileSync(file, 'utf8')
  const shim = /module\.exports\s*=\s*require\((?:"|')(?<path>\.\/\w+\.js)(?:"|')\)/.exec(source)
  if (shim?.groups?.['path']) {
    file = path.join(path.dirname(tscPath), shim.groups['path'])
    source = fs.readFileSync(file, 'utf8')
  }

  const patched = volar.transformTscContent(source, proxyApiPath, extra, remove, volarPath)
  const out = path.join(path.dirname(file), `.vue-tsc-bun-${process.pid}.js`)
  fs.writeFileSync(out, patched)
  try {
    return require(out)
  } finally {
    fs.rmSync(out, { force: true })
    delete require.cache[out]
  }
}

vueTsc.run()
