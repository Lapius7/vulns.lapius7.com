import { getState, setState } from './db.ts'
import { saveAdvisory } from './store.ts'

// GitHub reviewed advisories (GHSA) -> advisories table, so they can be listed and searched.
// Unauthenticated calls are limited to 60/hour, so each run stops when the quota is nearly used
// and resumes from the saved cursor on the next tick. Set GITHUB_TOKEN for 5000/hour.

const log = (...a: unknown[]) => console.log('[advsync]', ...a)
const SEV: Record<string, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', moderate: 'MEDIUM', low: 'LOW' }

const map = (a: any) => ({
  id: String(a.ghsa_id),
  summary: String(a.summary ?? ''),
  severity: SEV[String(a.severity ?? '').toLowerCase()] ?? null,
  cvss: a.cvss?.score != null ? String(a.cvss.score) : a.cvss_severities?.cvss_v4?.score != null ? String(a.cvss_severities.cvss_v4.score) : null,
  published: a.published_at,
  modified: a.updated_at,
  aliases: [a.cve_id].filter(Boolean),
  packages: ((a.vulnerabilities ?? []) as any[]).filter((v) => v.package?.name).map((v) => ({
    ecosystem: String(v.package.ecosystem ?? ''), name: String(v.package.name),
    ranges: v.vulnerable_version_range ? [String(v.vulnerable_version_range)] : [],
    fixed: v.first_patched_version ? [String(v.first_patched_version)] : [],
  })),
})

async function page(url: string) {
  const r = await fetch(url, { signal: AbortSignal.timeout(30_000), headers: {
    'user-agent': 'vulns.lapius7.com', accept: 'application/vnd.github+json',
    ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) } })
  const left = Number(r.headers.get('x-ratelimit-remaining') ?? 1)
  if (r.status === 403 || r.status === 429) return { items: null, next: null, left: 0 }
  if (!r.ok) throw new Error(String(r.status))
  const next = /<[^>]*[?&]after=([^&>]+)[^>]*>;\s*rel="next"/.exec(r.headers.get('link') ?? '')?.[1] ?? null
  return { items: (await r.json()) as any[], next: next && decodeURIComponent(next), left }
}

let running = false
export async function syncAdvisories() {
  if (running) return
  running = true
  try {
    const done = (await getState('adv_done')) === '1'
    const since = Number((await getState('adv_since')) ?? 0)
    let cursor = done ? null : await getState('adv_cursor')
    const started = Date.now()
    let n = 0
    for (;;) {
      const q = new URLSearchParams({ type: 'reviewed', per_page: '100', sort: done ? 'updated' : 'published', direction: 'desc' })
      if (cursor) q.set('after', cursor)
      const p = await page(`https://api.github.com/advisories?${q}`)
      if (!p.items) { log('rate limited, resume later'); break }
      let stop = false
      for (const a of p.items) {
        if (done && new Date(a.updated_at).getTime() < since) { stop = true; break }
        if (a.withdrawn_at) continue
        await saveAdvisory(map(a))
        n++
      }
      if (stop || !p.next) { await setState('adv_done', '1'); await setState('adv_since', String(started - 24 * 3600_000)); break }
      cursor = p.next
      if (!done) await setState('adv_cursor', cursor)
      if (p.left <= 3) { log('quota nearly used, resume later'); break }
    }
    if (n) log('saved', n)
  } catch (e: any) {
    log('error', e.message)
  } finally {
    running = false
  }
}
