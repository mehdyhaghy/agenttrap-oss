import type { Actor, Actors } from './api'
import { flag } from './format'

// The one-sentence verdict the Overview (and the email digest) opens with.
export type Mood = 'rogue' | 'agents' | 'quiet'

export interface Verdict { mood: Mood; headline: string; detail: string; deepest: Actor | null }

const n = (k: number, one: string, many: string): string => `${k} ${k === 1 ? one : many}`

// origins names up to three countries, most frequent first, with flags.
export function origins(actors: Actor[]): string {
  const count = new Map<string, { name: string; k: number }>()
  for (const a of actors) {
    if (!a.country_code) continue
    const c = count.get(a.country_code) ?? { name: a.country || a.country_code, k: 0 }
    c.k++
    count.set(a.country_code, c)
  }
  const top = [...count.entries()].sort((x, y) => y[1].k - x[1].k)
  const parts = top.slice(0, 3).map(([cc, c]) => `${flag(cc)} ${c.name}`)
  const extra = top.length - parts.length
  if (extra > 0) return `${parts.join(', ')} and ${n(extra, 'other country', 'other countries')}`
  if (parts.length < 2) return parts[0] ?? ''
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`
}

export function verdict(data: Actors, visitors: number, windowLabel: string): Verdict {
  const all = data.actors ?? []
  const rogue = all.filter((a) => a.class === 'rogue_agent')
  const agents = all.filter((a) => a.class === 'ai_agent')
  const pool = rogue.length ? rogue : agents
  const deepest = pool.reduce<Actor | null>((best, a) =>
    !best || a.capability > best.capability || (a.capability === best.capability && a.score > best.score) ? a : best, null)
  if (!pool.length) {
    return { mood: 'quiet', deepest: null, headline: 'All quiet — no agents took the bait',
      detail: `${n(visitors, 'visitor', 'visitors')} in the last ${windowLabel}. Scanners and crawlers are expected background noise.` }
  }
  const from = origins(pool)
  const detail = [
    deepest && deepest.capability > 0 ? `The deepest reached depth ${deepest.capability} of 7: ${deepest.depth}.` : '',
    from ? `From ${from}.` : '',
  ].filter(Boolean).join(' ')
  return rogue.length
    ? { mood: 'rogue', deepest, detail, headline: `${n(rogue.length, 'rogue agent', 'rogue agents')} took the bait` }
    : { mood: 'agents', deepest, detail, headline: `No rogue agents — ${n(agents.length, 'AI agent', 'AI agents')} came exploring` }
}

export function windowLabel(hours: number): string {
  return hours >= 48 && hours % 24 === 0 ? n(hours / 24, 'day', 'days') : n(hours, 'hour', 'hours')
}
