import type { Theme } from '@/components/arc/theme-switch/theme-switch'
import { useLang } from '@/lib/i18n'
import { Shell } from '@/Explore'

type Src = { name: string; url: string; en: string; ja: string; use: 'en' | 'ja' | 'both'; where: string }

// kind: how the source is used. db = synced into our database (searchable), live = fetched per page view.
const GROUPS: { en: string; ja: string; items: (Src & { kind: 'db' | 'live' })[] }[] = [
  { en: 'Core records (searchable)', ja: '本体データ (検索対象)', items: [
    { kind: 'db', name: 'NVD', url: 'https://nvd.nist.gov/', en: 'CVE records, CVSS, CWE, affected products, references', ja: 'CVE 本体、CVSS、CWE、影響製品、参照リンク', use: 'en', where: 'search, detail' },
    { kind: 'db', name: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', en: 'Vulnerabilities exploited in the wild, ransomware use', ja: '悪用が確認された脆弱性、ランサムウェア利用', use: 'en', where: 'search filter, KEV tab, detail' },
    { kind: 'db', name: 'EPSS (FIRST)', url: 'https://www.first.org/epss/', en: 'Exploit prediction score and history', ja: '悪用される確率のスコアと推移', use: 'en', where: 'search filter, EPSS tab, detail' },
    { kind: 'db', name: 'GitHub Advisory / OSV', url: 'https://osv.dev/', en: 'Package advisories (GHSA, PYSEC, RUSTSEC, Go ...)', ja: 'パッケージのアドバイザリ (GHSA、PYSEC、RUSTSEC、Go など)', use: 'en', where: 'package search, advisory pages' },
  ] },
  { en: 'Detail page extras (fetched per CVE)', ja: '詳細ページの追加情報 (CVE ごとに取得)', items: [
    { kind: 'live', name: 'CVE.org (MITRE)', url: 'https://www.cve.org/', en: 'Official record, affected versions, solutions, workarounds, credits', ja: '公式レコード、影響バージョン、対策、回避策、謝辞', use: 'en', where: 'detail' },
    { kind: 'live', name: 'JVN iPedia', url: 'https://jvndb.jvn.jp/', en: 'Japanese overview, impact and solution', ja: '日本語の概要、影響、対策', use: 'ja', where: 'detail' },
    { kind: 'live', name: 'CWE (MITRE)', url: 'https://cwe.mitre.org/', en: 'Weakness names', ja: '脆弱性の種類の名称', use: 'en', where: 'detail, CWE filter' },
  ] },
  { en: 'Exploits and PoCs', ja: 'エクスプロイト・PoC', items: [
    { kind: 'live', name: 'Exploit-DB', url: 'https://www.exploit-db.com/', en: 'Public exploits', ja: '公開されているエクスプロイト', use: 'en', where: 'detail' },
    { kind: 'live', name: 'Metasploit', url: 'https://github.com/rapid7/metasploit-framework', en: 'Exploit modules', ja: '攻撃モジュール', use: 'en', where: 'detail' },
    { kind: 'live', name: 'Nuclei templates', url: 'https://github.com/projectdiscovery/nuclei-templates', en: 'Scanner templates', ja: 'スキャナ用テンプレート', use: 'en', where: 'detail' },
    { kind: 'live', name: 'PoC-in-GitHub', url: 'https://github.com/nomi-sec/PoC-in-GitHub', en: 'PoC repositories on GitHub', ja: 'GitHub 上の PoC リポジトリ', use: 'en', where: 'detail' },
    { kind: 'live', name: 'Trickest CVE', url: 'https://github.com/trickest/cve', en: 'Aggregated PoC links', ja: 'PoC リンクのまとめ', use: 'en', where: 'detail' },
  ] },
  { en: 'Vendors and community', ja: 'ベンダー・コミュニティ', items: [
    { kind: 'live', name: 'Ubuntu Security', url: 'https://ubuntu.com/security/cves', en: 'Fix status per release', ja: 'リリースごとの修正状況', use: 'en', where: 'detail' },
    { kind: 'live', name: 'Red Hat Security', url: 'https://access.redhat.com/security/security-updates/', en: 'Severity and fix status', ja: '深刻度と修正状況', use: 'en', where: 'detail' },
    { kind: 'live', name: 'Microsoft MSRC', url: 'https://msrc.microsoft.com/update-guide', en: 'Exploited / disclosed status', ja: '悪用・公開の状況', use: 'en', where: 'detail' },
    { kind: 'live', name: 'Hacker News', url: 'https://news.ycombinator.com/', en: 'Discussion threads mentioning the CVE', ja: 'CVE に言及したスレッド', use: 'en', where: 'detail' },
  ] },
]

const T = {
  ja: { title: '情報源一覧', lead: 'このサイトが参照しているデータの出どころです。すべて無料の公開データで、認証は不要です。', name: '名称', what: '内容', lang: '言語', where: '表示場所', db: '検索対象 (同期済み)', live: '詳細ページで取得', note: '公表前の CVE (予約のみ) は、NVD や CVE.org に載るまで表示されません。', en: '英語', ja: '日本語' },
  en: { title: 'Data sources', lead: 'Where the data on this site comes from. All are free public data and need no authentication.', name: 'Name', what: 'Content', lang: 'Language', where: 'Shown in', db: 'Searchable (synced)', live: 'Fetched on detail pages', note: 'CVE IDs that are only reserved (not yet published) do not appear until NVD or CVE.org lists them.', en: 'English', ja: 'Japanese' },
} as const

export default function SourcesPage({ theme, onThemeChange }: { theme: Theme; onThemeChange: (t: Theme, v: unknown, el: HTMLElement) => void }) {
  const { lang } = useLang()
  const x = T[lang === 'ja' ? 'ja' : 'en']
  return (
    <Shell title={x.title} crumb={x.lead} theme={theme} onThemeChange={onThemeChange}>
      <div className="doc">
        {GROUPS.map((g) => <section key={g.en}>
          <h2>{lang === 'ja' ? g.ja : g.en}</h2>
          <div className="tw"><table><thead><tr><th>{x.name}</th><th>{x.what}</th><th>{x.lang}</th><th>{x.where}</th></tr></thead><tbody>
            {g.items.map((s) => <tr key={s.name}>
              <td><a href={s.url} target="_blank" rel="noopener noreferrer">{s.name}</a><br /><span className="tags">{s.kind === 'db' ? x.db : x.live}</span></td>
              <td>{lang === 'ja' ? s.ja : s.en}</td>
              <td>{x[s.use as 'en' | 'ja']}</td>
              <td>{s.where}</td>
            </tr>)}
          </tbody></table></div>
        </section>)}
        <p className="tags">{x.note}</p>
      </div>
    </Shell>
  )
}
