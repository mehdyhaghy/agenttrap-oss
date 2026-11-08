import type { ActorClass } from './api'

export interface ClassMeta { key: ActorClass; label: string; plural: string; icon: string; color: string; blurb: string }

// Each class has its own color, shared with the email digest; rogue agents
// carry the critical red. Every badge also shows an icon and a label, so
// color never carries meaning alone.
export const CLASSES: ClassMeta[] = [
  { key: 'rogue_agent', label: 'Rogue agent', plural: 'Rogue agents', icon: '⚑', color: 'var(--c-rogue)', blurb: 'Used a planted credential' },
  { key: 'ai_agent', label: 'AI agent', plural: 'AI agents', icon: '◆', color: 'var(--c-agent)', blurb: 'Reads and acts on agent-facing content' },
  { key: 'scanner', label: 'Scanner', plural: 'Scanners', icon: '▲', color: 'var(--c-scanner)', blurb: 'Probing, exploits or reconnaissance' },
  { key: 'crawler', label: 'Crawler', plural: 'Crawlers', icon: '●', color: 'var(--c-crawler)', blurb: 'Declared bot fetching pages' },
  { key: 'browser', label: 'Browser-like', plural: 'Browser-like', icon: '○', color: 'var(--c-browser)', blurb: 'Browser user agent, not yet verified' },
  { key: 'unknown', label: 'Unknown', plural: 'Unknown', icon: '·', color: 'var(--c-unknown)', blurb: 'Too little activity to judge' },
  { key: 'operator', label: 'Operator', plural: 'Operator (you)', icon: '✓', color: 'var(--text-muted)', blurb: 'Your own traffic, excluded' },
]

// Classes shown in totals; operator traffic is ours and stays out of them.
export const VISITOR_CLASSES = CLASSES.filter((c) => c.key !== 'operator')

export function classMeta(key: string): ClassMeta {
  return CLASSES.find((c) => c.key === key) ?? (CLASSES[CLASSES.length - 1] as ClassMeta)
}
