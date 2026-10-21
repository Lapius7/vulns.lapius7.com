import { useEffect, useLayoutEffect, useState } from 'react'
import { SearchField } from '@/components/arc/search-field/search-field'
import { Select } from '@/components/arc/select/select'
import SegmentedControl from '@/components/arc/segmented-control/segmented-control'
import { Pagination } from '@/components/arc/pagination/pagination'
import { Button } from '@/components/arc/button/button'
import { Input } from '@/components/arc/input/input'
import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { useThemeTransition } from '@/components/transitions/theme-transition'
import { ThemeSwitch, type Theme } from '@/components/arc/theme-switch/theme-switch'
import { searchAdvisories, searchProducts, type AdvItem, type ProdItem, ADV_KEYS, ADV_RE, getAdvisory, getEpssTop, type Advisory, getKev, searchCves, type EpssItem, type Feed, type KevItem, type CveList } from '@/lib/api'
import { Link, stripLang, usePath, withLang } from '@/lib/router'
import { useLang, type Lang } from '@/lib/i18n'
import Detail from '@/Detail'
import EmptyArt from '@/EmptyArt'
import AdvisoryDetail from '@/Advisory'
import ScanPage from '@/Scan'
import StatsPage from '@/Stats'
import DocsPage from '@/Docs'
import SourcesPage from '@/Sources'
import { Shell } from '@/Explore'
import { classify } from '@/lib/query'
import { ProductSuggest } from '@/ProductSuggest'
import { CwePage, PkgPage, VendorPage } from '@/Explore'
import DataTable from '@/components/data-table'
import { cveColumns, epssColumns, kevColumns } from '@/columns'

function useDebounced<T>(v: T, ms: number) {
  const [d, setD] = useState(v)
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms)
    return () => clearTimeout(t)
  }, [v, ms])
  return d
}

function NotFoundPage({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t } = useLang()
  return <Shell title={t('pageNotFound')} theme={theme} onThemeChange={onThemeChange}>
    <EmptyState title={t('pageNotFound')} description={t('pageNotFoundHint')} action={<Link href="/"><Button>{t('back')}</Button></Link>} />
  </Shell>
}

export default function App() {
  const path = usePath()
  const { resolvedTheme: theme, setTheme: applyTheme } = useThemeTransition()
  useLayoutEffect(() => { document.documentElement.dataset.theme = theme }, [theme])
  const setTheme = (next: Theme, _v: unknown, trigger: HTMLElement) => applyTheme(next, { origin: trigger })
  const rest = stripLang(path)
  const dec = (x: string) => { try { return decodeURIComponent(x) } catch { return x } }
  const tp = { theme, onThemeChange: setTheme }
  const pk = rest.match(/^\/pkg(?:\/([^/]+)(?:\/(.+?))?)?\/?$/)
  if (pk) return <PkgPage eco={pk[1] ?? ''} name={dec(pk[2] ?? '')} {...tp} />
  if (/^\/scan\/?$/.test(rest)) return <ScanPage {...tp} />
  if (/^\/stats\/?$/.test(rest)) return <StatsPage {...tp} />
  if (/^\/docs\/?$/.test(rest)) return <DocsPage {...tp} />
  if (/^\/sources\/?$/.test(rest)) return <SourcesPage {...tp} />
  const vd = rest.match(/^\/vendor\/([^/]+)(?:\/([^/]+))?\/?$/)
  if (vd) return <VendorPage vendor={dec(vd[1])} product={dec(vd[2] ?? '')} {...tp} />
  const cw = rest.match(/^\/cwe\/([\w-]+)\/?$/i)
  if (cw) return <CwePage id={cw[1]} {...tp} />
  const m = rest.match(/^\/([A-Za-z]+-[A-Za-z0-9-]{4,40})\/?$/)
  const vid = m && (ADV_RE.test(m[1]) || /^CVE-\d{4}-\d{4,}$/i.test(m[1])) ? decodeURIComponent(m[1]) : ''
  // Anything that is not the top page and matched no route above is a 404, not the home page.
  if (!vid && rest !== '' && rest !== '/') return <NotFoundPage {...tp} />
  return vid ? (ADV_RE.test(vid) && !/^CVE-/i.test(vid) ? <AdvisoryDetail id={vid} theme={theme} onThemeChange={setTheme} /> : <Detail id={vid} theme={theme} onThemeChange={setTheme} />) : <Home theme={theme} onThemeChange={setTheme} />
}

export function LangSwitch() {
  const { lang, setLang, t } = useLang()
  return (
    <SegmentedControl label={t('aLanguage')} value={lang} onValueChange={(v) => setLang(v as Lang)}
      options={[{ value: 'en', label: 'EN' }, { value: 'ja', label: '日本語' }]} />
  )
}

type Tab = 'search' | 'kev' | 'epss'


const normAdv = (id: string) => /^ghsa-/i.test(id) ? `GHSA-${id.slice(5).toLowerCase()}` : id.toUpperCase()

function AdvRow({ a }: { a: AdvItem }) {
  const { t } = useLang()
  return <Link href={`/${a.id}`} className="row">
    <span className="id">{a.id}</span>
    <span className="desc">{a.summary}<span className="tags" style={{ display: 'block' }}>{[...new Set(a.packages.map((p) => `${p.ecosystem}: ${p.name}`))].slice(0, 3).join(' · ')}{a.aliases.length ? ` · ${a.aliases.join(', ')}` : ''}</span></span>
    <span className="tags">{a.severity ? t(a.severity.toLowerCase() as 'critical') : ''} {a.published?.slice(0, 10)}</span>
  </Link>
}

function ProdRow({ p }: { p: ProdItem }) {
  return <Link href={`/vendor/${encodeURIComponent(p.vendor)}/${encodeURIComponent(p.product)}`} className="row">
    <span className="id">{p.vendor}</span>
    <span className="desc">{p.product}</span>
    <span className="tags">{p.count.toLocaleString()} CVE</span>
  </Link>
}

function Home({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { t } = useLang()
  const init = new URLSearchParams(location.search)
  const [tab, setTab] = useState<Tab>((init.get('tab') as Tab) || 'search')
  const [q, setQ] = useState(init.get('q') ?? '')
  const [severity, setSeverity] = useState(init.get('severity') ?? '')
  const [year, setYear] = useState(init.get('year') ?? '')
  const [sort, setSort] = useState(init.get('sort') ?? '')
  const [kind, setKind] = useState(init.get('kind') ?? '')
  const [other, setOther] = useState<Feed<AdvItem> | Feed<ProdItem> | null>(null)
  const [prev, setPrev] = useState<{ adv: Feed<AdvItem>; prod: Feed<ProdItem> } | null>(null)
  const [adv, setAdv] = useState<Record<string, string>>(() => Object.fromEntries(ADV_KEYS.map((k) => [k, init.get(k) ?? '']).filter(([, v]) => v)))
  const [advOpen, setAdvOpen] = useState(() => ADV_KEYS.some((k) => init.get(k)))
  const setA = (k: string, v: string) => { setAdv((a) => ({ ...a, [k]: v })); setPage(1) }
  const advCount = Object.values(adv).filter(Boolean).length
  const [page, setPage] = useState(Number(init.get('page')) || 1)
  const [data, setData] = useState<CveList | null>(null)
  const [kev, setKev] = useState<Feed<KevItem> | null>(null)
  const [top, setTop] = useState<Feed<EpssItem> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  const dq = useDebounced(q.trim(), 600)
  // A GHSA / OSV style ID, or a GitHub advisory URL, links straight to its advisory page.
  const gh = q.trim().match(/github\.com\/([\w.-]+\/[\w.-]+)\/security\/advisories\/(GHSA(?:-[a-z0-9]{4}){3})/i)
  const advId = gh ? gh[2].toLowerCase().replace('ghsa', 'GHSA') : ADV_RE.test(q.trim()) && !/^CVE-/i.test(q.trim()) ? normAdv(q.trim()) : null
  const [advInfo, setAdvInfo] = useState<Advisory | null>(null)
  const intents = classify(q)
  const advHref = advId ? `/${advId}${gh ? `?repo=${gh[1]}` : ''}` : null
  const narrow = matchMedia('(max-width: 40rem)').matches

  useEffect(() => {
    setAdvInfo(null)
    if (!advId) return
    const ac = new AbortController()
    const h = setTimeout(() => getAdvisory(advId, gh?.[1], ac.signal).then(setAdvInfo).catch(() => {}), 400)
    return () => { clearTimeout(h); ac.abort() }
  }, [advId, gh?.[1]])

  useEffect(() => {
    const p = new URLSearchParams()
    if (tab !== 'search') p.set('tab', tab)
    if (tab === 'search' && dq) p.set('q', dq)
    if (tab === 'search' && severity) p.set('severity', severity)
    if (tab === 'search' && year) p.set('year', year)
    if (tab === 'search' && sort) p.set('sort', sort)
    if (tab === 'search') for (const [k, v] of Object.entries(adv)) if (v) p.set(k, v)
    if (tab === 'search' && kind) p.set('kind', kind)
    if (page > 1) p.set('page', String(page))
    history.replaceState(null, '', p.size ? `?${p}` : location.pathname)
  }, [tab, dq, severity, year, sort, adv, kind, page])

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    const fail = (e: Error) => { if (e.name !== 'AbortError') { setError(e.message === 'rate_limited' ? 'rate' : 'loadFail'); setLoading(false) } }
    const onlyOther = tab === 'search' && (kind === 'adv' || kind === 'prod')
    if (onlyOther && kind === 'adv') searchAdvisories(dq, severity, page, ac.signal, sort).then((d) => { setOther(d); setLoading(false) }).catch(fail)
    else if (onlyOther) searchProducts(dq, page, ac.signal).then((d) => { setOther(d); setLoading(false) }).catch(fail)
    else if (tab === 'search') {
      searchCves(dq, severity, page, ac.signal, year, sort, adv).then((d) => { setData(d); setLoading(false) }).catch(fail)
      setPrev(null)
      if (kind === '' && dq.length >= 2 && page === 1) Promise.all([searchAdvisories(dq, severity, 1, ac.signal), searchProducts(dq, 1, ac.signal)]).then(([a, pr]) => setPrev({ adv: a, prod: pr })).catch(() => {})
    }
    else if (tab === 'kev') getKev(page, ac.signal).then((d) => { setKev(d); setLoading(false) }).catch(fail)
    else getEpssTop(page, ac.signal).then((d) => { setTop(d); setLoading(false) }).catch(fail)
    return () => ac.abort()
  }, [tab, dq, severity, year, sort, adv, kind, page, nonce])

  const onlyOther = tab === 'search' && (kind === 'adv' || kind === 'prod')
  const feed = onlyOther ? other : tab === 'search' ? data : tab === 'kev' ? kev : top
  const pageCount = feed?.perPage ? Math.ceil((feed.total ?? 0) / feed.perPage) : 0
  const sevOptions = [
    { value: '', label: t('all') }, { value: 'CRITICAL', label: t('critical') }, { value: 'HIGH', label: t('high') },
    { value: 'MEDIUM', label: t('medium') }, { value: 'LOW', label: t('low') },
  ]

  return (
    <main className="page">
      <div className="top">
        <h1>{t('title')}</h1>
        <div className="actions"><LangSwitch /><ThemeSwitch theme={theme} onThemeChange={onThemeChange} iconOnly /></div>
      </div>
      <p className="lead">{t('lead')}</p>
      <nav className="tags" style={{ display: 'flex', gap: '1rem', margin: '-.5rem 0 1rem', fontSize: '.875rem' }}><Link href="/pkg">{t('navPkg')}</Link><Link href="/scan">{t('navScan')}</Link><Link href="/stats">{t('navStats')}</Link><Link href="/sources">{t('navSources')}</Link><Link href="/docs">{t('navDocs')}</Link></nav>

      <div className="tabs" style={{ marginBottom: '1rem' }}>
        <SegmentedControl label={t('aView')} value={tab} onValueChange={(v) => { setTab(v as Tab); setPage(1) }}
          options={[{ value: 'search', label: t('tabSearch') }, { value: 'kev', label: t('tabKev') }, { value: 'epss', label: t('tabEpss') }]} />
      </div>

      {tab === 'search' ? (
        <div className="controls">
          <div className="grow">
            <SearchField autoComplete="off" spellCheck={false} label={t('searchLabel')} placeholder={t('searchPh')} value={q} onValueChange={(v) => { setQ(v); setPage(1) }} />
          </div>
          <SegmentedControl label={t('kindLabel')} options={[{ value: '', label: t('kindAll') }, { value: 'cve', label: 'CVE' }, { value: 'adv', label: t('kindAdv') }, { value: 'prod', label: t('kindProd') }]} value={kind} onValueChange={(v) => { setKind(v); setPage(1); setOther(null) }} />
          <SegmentedControl label={t('severity')} options={sevOptions} value={severity} onValueChange={(v) => { setSeverity(v); setPage(1) }} />
          <Select label={t('year')} value={year || '_'} onValueChange={(v) => { setYear(v === '_' ? '' : v); setPage(1) }} options={[{ value: '_', label: t('anyYear') }, ...Array.from({ length: new Date().getFullYear() - 1998 }, (_, i) => String(new Date().getFullYear() - i)).map((y) => ({ value: y, label: y }))]} />
          <Select label={t('sortBy')} value={sort || '_'} onValueChange={(v) => { setSort(v === '_' ? '' : v); setPage(1) }} options={[{ value: '_', label: t('sortNew') }, { value: 'score', label: t('sortScore') }, { value: 'epss', label: t('sortEpss') }, { value: 'modified', label: t('sortModified') }, { value: 'old', label: t('sortOld') }]} />
          <Button variant="secondary" size="sm" onClick={() => setAdvOpen((o) => !o)} aria-expanded={advOpen}>{t('advFilters')}{advCount > 0 ? ` (${advCount})` : ''}</Button>
        </div>
      ) : (
        <p className="lead" style={{ marginTop: 0 }}>{t(tab === 'kev' ? 'kevLead' : 'epssLead')}</p>
      )}

      {tab === 'search' && advOpen && <div className="advpanel card">
        <Input label={t('fMinScore')} type="number" inputMode="decimal" min={0} max={10} step={0.1} value={adv.minScore ?? ''} onChange={(e) => setA('minScore', e.target.value)} />
        <Input label={t('fMaxScore')} type="number" inputMode="decimal" min={0} max={10} step={0.1} value={adv.maxScore ?? ''} onChange={(e) => setA('maxScore', e.target.value)} />
        <Input label={t('fMinEpss')} type="number" inputMode="decimal" min={0} max={100} step={1} value={adv.minEpss ? String(Math.round(Number(adv.minEpss) * 100)) : ''} onChange={(e) => setA('minEpss', e.target.value === '' ? '' : String(Math.min(100, Math.max(0, Number(e.target.value))) / 100))} />
        <Input label={t('fFrom')} type="date" value={adv.from ?? ''} onChange={(e) => setA('from', e.target.value)} />
        <Input label={t('fTo')} type="date" value={adv.to ?? ''} onChange={(e) => setA('to', e.target.value)} />
        <Input label={t('fCwe')} placeholder="CWE-79" value={adv.cwe ?? ''} onChange={(e) => setA('cwe', e.target.value)} />
        <Input label={t('fVendor')} placeholder="microsoft" value={adv.vendor ?? ''} onChange={(e) => setA('vendor', e.target.value)} />
        <Input label={t('fProduct')} placeholder="windows_11" value={adv.product ?? ''} onChange={(e) => setA('product', e.target.value)} />
        <Select label={t('fAv')} value={adv.av || '_'} onValueChange={(v) => setA('av', v === '_' ? '' : v)} options={[{ value: '_', label: t('any') }, { value: 'N', label: t('mNetwork') }, { value: 'A', label: t('mAdjacent') }, { value: 'L', label: t('mLocal') }, { value: 'P', label: t('mPhysical') }]} />
        <Select label={t('fAc')} value={adv.ac || '_'} onValueChange={(v) => setA('ac', v === '_' ? '' : v)} options={[{ value: '_', label: t('any') }, { value: 'L', label: t('mLow') }, { value: 'H', label: t('mHigh') }]} />
        <Select label={t('fPr')} value={adv.pr || '_'} onValueChange={(v) => setA('pr', v === '_' ? '' : v)} options={[{ value: '_', label: t('any') }, { value: 'N', label: t('mNone') }, { value: 'L', label: t('mLow') }, { value: 'H', label: t('mHigh') }]} />
        <Select label={t('fUi')} value={adv.ui || '_'} onValueChange={(v) => setA('ui', v === '_' ? '' : v)} options={[{ value: '_', label: t('any') }, { value: 'N', label: t('mNone') }, { value: 'R', label: t('mRequired') }]} />
        <Select label={t('fCvss')} value={adv.cvss || '_'} onValueChange={(v) => setA('cvss', v === '_' ? '' : v)} options={[{ value: '_', label: t('any') }, { value: '4.0', label: 'CVSS 4.0' }, { value: '3.1', label: 'CVSS 3.1' }, { value: '3.0', label: 'CVSS 3.0' }, { value: '2.0', label: 'CVSS 2.0' }]} />
        <label className="advchk"><input type="checkbox" checked={adv.kev === '1'} onChange={(e) => setA('kev', e.target.checked ? '1' : '')} /> {t('fKev')}</label>
        <label className="advchk"><input type="checkbox" checked={adv.ransomware === '1'} onChange={(e) => setA('ransomware', e.target.checked ? '1' : '')} /> {t('fRansom')}</label>
        <label className="advchk"><input type="checkbox" checked={adv.noRejected === '1'} onChange={(e) => setA('noRejected', e.target.checked ? '1' : '')} /> {t('fNoReject')}</label>
        {advCount > 0 && <Button variant="ghost" size="sm" onClick={() => { setAdv({}); setPage(1) }}>{t('fReset')}</Button>}
      </div>}

      {intents.length > 0 && <div className="card" style={{ margin: '0 0 .75rem', display: 'grid', gap: '.25rem' }}>
        {intents.map((it) => <p key={it.href} style={{ margin: 0 }}><Link href={it.href}>{t(it.kind === 'pkg' ? 'openPkg' : it.kind === 'vendor' ? 'openVendor' : it.kind === 'cwe' ? 'openCwe' : 'openCve', { x: it.label })}</Link></p>)}
      </div>}
      {tab === 'search' && !intents.length && !advId && <ProductSuggest q={dq} />}
      {advHref && <div className="card" style={{ margin: '0 0 .75rem' }}>
        <p style={{ margin: 0 }}><Link href={advHref}>{t('openAdv', { id: advId! })}</Link></p>
        <p className="tags" style={{ margin: '.25rem 0 0' }}>{advInfo?.summary || t(gh ? 'advRepoHint' : 'advHint')}{advInfo?.severity && ` (${t(advInfo.severity.toLowerCase() as 'critical')})`}</p>
      </div>}
      <div className="meta" aria-live="polite">
        {error ? '' : loading ? t('searching') : feed && t(tab === 'search' && !dq && data?.live ? 'recent' : 'results', { n: (feed.total ?? 0).toLocaleString() })}
      </div>

      {error ? (
        <EmptyState title={t('errorTitle')} description={t(error as 'rate')} action={<Button onClick={() => setNonce((n) => n + 1)}>{t('retry')}</Button>} />
      ) : loading && !feed ? (
        <Skeleton label={t('searching')} lines={6} />
      ) : feed && feed.items.length === 0 ? (
        <div className="empty-art"><EmptyState icon={<EmptyArt />} title={t('noneTitle')} description={t('none')} /></div>
      ) : (
        <div className="list" style={{ opacity: loading ? 0.6 : 1, transition: 'opacity .15s' }}>
          {onlyOther && kind === 'adv' && other && (other.items as AdvItem[]).map((a) => <AdvRow key={a.id} a={a} />)}
          {onlyOther && kind === 'prod' && other && (other.items as ProdItem[]).map((pr) => <ProdRow key={`${pr.vendor}/${pr.product}`} p={pr} />)}
          {tab === 'search' && !onlyOther && data && <DataTable key="s" data={data.items} columns={cveColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} initialVisibility={narrow ? { package: false, description: false, epss: false, published: false } : {}} />}
          {tab === 'kev' && kev && <DataTable key="k" data={kev.items} columns={kevColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} initialVisibility={narrow ? { description: false, due: false, vendor: false, added: false, ransomware: false } : { ransomware: false, due: false }} />}
          {tab === 'epss' && top && <DataTable key="e" data={top.items} columns={epssColumns(t)} columnsLabel={t('columns')} rowHref={(c) => withLang(`/${c.id}`)} />}
        </div>
      )}

      {tab === 'search' && kind === '' && prev && (prev.adv.items.length > 0 || prev.prod.items.length > 0) && <div className="prev">
        {prev.adv.items.length > 0 && <section><h3>{t('kindAdv')} <span className="tags">{prev.adv.total.toLocaleString()}</span></h3>
          <div className="list">{prev.adv.items.slice(0, 5).map((a) => <AdvRow key={a.id} a={a} />)}</div>
          {prev.adv.total > 5 && <p><Button variant="ghost" size="sm" onClick={() => { setKind('adv'); setPage(1) }}>{t('kindMore')}</Button></p>}</section>}
        {prev.prod.items.length > 0 && <section><h3>{t('kindProd')} <span className="tags">{prev.prod.total.toLocaleString()}</span></h3>
          <div className="list">{prev.prod.items.slice(0, 5).map((pr) => <ProdRow key={`${pr.vendor}/${pr.product}`} p={pr} />)}</div>
          {prev.prod.total > 5 && <p><Button variant="ghost" size="sm" onClick={() => { setKind('prod'); setPage(1) }}>{t('kindMore')}</Button></p>}</section>}
      </div>}

      {pageCount > 1 && (
        <div className="pager">
          <Pagination page={page} pageCount={Math.min(pageCount, 500)} onPageChange={(p) => { setPage(p); scrollTo({ top: 0 }) }} />
        </div>
      )}
    </main>
  )
}
