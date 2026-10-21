import { j } from './sources.ts'

// Extra free, key-less sources: public exploits / PoCs, vendor advisories and community mentions.
// Bulk datasets (Exploit-DB, Metasploit, Nuclei) are indexed in memory by CVE ID and refreshed lazily.

const UA = { 'user-agent': 'vulns.lapius7.com' }
const text = async (url: string, ms = 60_000) => {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms), headers: UA })
  if (!r.ok) throw new Error(String(r.status))
  return r.text()
}

const CVE_IN = /CVE-\d{4}-\d{4,}/gi
const REFRESH = 12 * 3600_000

function lazyIndex<T>(load: () => Promise<Map<string, T[]>>) {
  let map = new Map<string, T[]>()
  let at = 0
  let busy: Promise<void> | null = null
  return async (id: string): Promise<T[]> => {
    if (Date.now() - at > REFRESH && !busy) {
      busy = load().then((m) => { map = m; at = Date.now() }).catch(() => { at = Date.now() - REFRESH + 600_000 }).finally(() => { busy = null })
    }
    if (busy && !at) await busy
    return map.get(id) ?? []
  }
}

function push<T>(m: Map<string, T[]>, id: string, v: T) {
  const k = id.toUpperCase()
  const a = m.get(k)
  if (a) a.push(v); else m.set(k, [v])
}

/** Minimal RFC 4180 parser (quoted fields, embedded commas / newlines). */
function* csvRows(src: string) {
  let row: string[] = [], f = '', q = false
  for (let i = 0; i < src.length; i++) {
    const c = src[i]
    if (q) {
      if (c === '"') { if (src[i + 1] === '"') { f += '"'; i++ } else q = false } else f += c
    } else if (c === '"') q = true
    else if (c === ',') { row.push(f); f = '' }
    else if (c === '\n') { row.push(f); f = ''; yield row; row = [] }
    else if (c !== '\r') f += c
  }
  if (f || row.length) { row.push(f); yield row }
}

export interface ExploitDb { id: string; title: string; type: string; platform: string; published: string; author: string; verified: boolean; url: string }
const exploitDb = lazyIndex<ExploitDb>(async () => {
  const m = new Map<string, ExploitDb[]>()
  const it = csvRows(await text('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', 120_000))
  const head = it.next().value as string[]
  const ix = (n: string) => head.indexOf(n)
  const [iId, iDesc, iPub, iAuth, iType, iPlat, iVer, iCodes] = ['id', 'description', 'date_published', 'author', 'type', 'platform', 'verified', 'codes'].map(ix)
  for (const r of it) {
    for (const cve of (r[iCodes] ?? '').match(CVE_IN) ?? []) {
      push(m, cve, { id: r[iId], title: r[iDesc], type: r[iType], platform: r[iPlat], published: r[iPub], author: r[iAuth], verified: r[iVer] === '1', url: `https://www.exploit-db.com/exploits/${r[iId]}` })
    }
  }
  return m
})

export interface Msf { name: string; module: string; type: string; rank: number; disclosed: string | null; url: string }
const metasploit = lazyIndex<Msf>(async () => {
  const d = JSON.parse(await text('https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json', 120_000)) as Record<string, any>
  const m = new Map<string, Msf[]>()
  for (const v of Object.values(d)) {
    for (const ref of (v.references ?? []) as string[]) {
      if (/^CVE-\d{4}-\d{4,}$/i.test(ref)) push(m, ref, { name: v.name, module: v.fullname, type: v.type, rank: v.rank, disclosed: v.disclosure_date ?? null, url: `https://github.com/rapid7/metasploit-framework/blob/master${v.path}` })
    }
  }
  return m
})

export interface Nuclei { name: string; severity: string; url: string }
const nuclei = lazyIndex<Nuclei>(async () => {
  const m = new Map<string, Nuclei[]>()
  for (const line of (await text('https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json', 120_000)).split('\n')) {
    if (!line.trim()) continue
    try {
      const o = JSON.parse(line)
      push(m, o.ID, { name: o.Info?.Name ?? o.ID, severity: o.Info?.Severity ?? '', url: `https://github.com/projectdiscovery/nuclei-templates/blob/main/${o.file_path}` })
    } catch { /* skip bad line */ }
  }
  return m
})

const year = (id: string) => id.split('-')[1]

export interface Poc { repo: string; url: string; description: string; stars: number; updated: string }
async function pocGithub(id: string): Promise<Poc[]> {
  try {
    const d = (await j(`https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${year(id)}/${id}.json`, 10_000)) as any[]
    return d.map((r) => ({ repo: String(r.full_name), url: String(r.html_url), description: String(r.description ?? '').slice(0, 200), stars: Number(r.stargazers_count) || 0, updated: String(r.pushed_at ?? r.updated_at ?? '').slice(0, 10) }))
      .sort((a, b) => b.stars - a.stars).slice(0, 15)
  } catch { return [] }
}

/** Trickest aggregates PoC links per CVE as markdown. */
async function trickest(id: string): Promise<string[]> {
  try {
    const md = await text(`https://raw.githubusercontent.com/trickest/cve/main/${year(id)}/${id}.md`, 10_000)
    const sec = md.split(/^####\s+Github/im)[1] ?? ''
    return [...new Set([...sec.matchAll(/https?:\/\/[^\s)<>]+/g)].map((x) => x[0]))].slice(0, 20)
  } catch { return [] }
}

export interface Distro { vendor: string; severity: string | null; url: string; states: { product: string; status: string; fixed?: string }[] }
async function ubuntu(id: string): Promise<Distro | null> {
  try {
    const d: any = await j(`https://ubuntu.com/security/cves/${id}.json`, 10_000)
    const states: Distro['states'] = []
    for (const p of d.packages ?? []) {
      for (const s of p.statuses ?? []) {
        if (s.status === 'DNE' || s.status === 'not-affected') continue
        states.push({ product: `${p.name} (${s.release_codename})`, status: String(s.status), fixed: s.description || undefined })
      }
    }
    return { vendor: 'Ubuntu', severity: d.priority ?? null, url: `https://ubuntu.com/security/${id}`, states: states.slice(0, 30) }
  } catch { return null }
}

async function redhat(id: string): Promise<Distro | null> {
  try {
    const d: any = await j(`https://access.redhat.com/hydra/rest/securitydata/cve/${id}.json`, 10_000)
    const states: Distro['states'] = [
      ...(d.affected_release ?? []).map((a: any) => ({ product: String(a.product_name), status: 'Fixed', fixed: [a.package, a.advisory].filter(Boolean).join(' / ') || undefined })),
      ...(d.package_state ?? []).filter((p: any) => p.fix_state !== 'Not affected').map((p: any) => ({ product: `${p.product_name}: ${p.package_name}`, status: String(p.fix_state) })),
    ]
    return { vendor: 'Red Hat', severity: d.threat_severity ?? null, url: `https://access.redhat.com/security/cve/${id}`, states: states.slice(0, 30) }
  } catch { return null }
}

export interface Msrc { title: string; released: string; exploited: string; disclosed: string; exploitability: string | null; url: string }
async function msrc(id: string): Promise<Msrc | null> {
  try {
    const d: any = await j(`https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?%24filter=${encodeURIComponent(`cveNumber eq '${id}'`)}`, 10_000)
    const v = d.value?.[0]
    if (!v) return null
    return { title: String(v.cveTitle), released: String(v.releaseDate).slice(0, 10), exploited: String(v.exploited ?? ''), disclosed: String(v.publiclyDisclosed ?? ''), exploitability: v.latestSoftwareRelease ?? null, url: `https://msrc.microsoft.com/update-guide/vulnerability/${id}` }
  } catch { return null }
}

export interface Mention { title: string; url: string; points: number; comments: number; date: string; site: string }
async function hackerNews(id: string): Promise<Mention[]> {
  try {
    const d: any = await j(`https://hn.algolia.com/api/v1/search?query=${id}&tags=story&hitsPerPage=10`, 8000)
    return (d.hits ?? []).map((h: any) => ({ title: String(h.title), url: `https://news.ycombinator.com/item?id=${h.objectID}`, points: h.points ?? 0, comments: h.num_comments ?? 0, date: String(h.created_at).slice(0, 10), site: 'Hacker News' }))
  } catch { return [] }
}

export interface Intel {
  exploitdb: ExploitDb[]
  metasploit: Msf[]
  nuclei: Nuclei[]
  pocs: Poc[]
  trickest: string[]
  distros: Distro[]
  msrc: Msrc | null
  mentions: Mention[]
}

export async function intel(id: string): Promise<Intel> {
  const [edb, msf, nu, pocs, tr, ub, rh, ms, hn] = await Promise.all([
    exploitDb(id), metasploit(id), nuclei(id), pocGithub(id), trickest(id), ubuntu(id), redhat(id), msrc(id), hackerNews(id),
  ])
  return { exploitdb: edb, metasploit: msf, nuclei: nu, pocs, trickest: tr, distros: [ub, rh].filter((x): x is Distro => !!x), msrc: ms, mentions: hn }
}

/** True when any public exploit / PoC / scanner template is known (used for the exploit badge). */
export const hasExploit = (i: Intel) => i.exploitdb.length + i.metasploit.length + i.nuclei.length + i.pocs.length > 0
