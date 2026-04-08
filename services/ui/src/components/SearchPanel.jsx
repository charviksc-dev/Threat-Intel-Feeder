import { useState } from 'react'

export default function SearchPanel({ axiosClient }) {
  const [query, setQuery] = useState('')
  const [filters, setFilters] = useState({ type: '', source: '', severity: '', minScore: '' })
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [enrichData, setEnrichData] = useState(null)
  const [huntData, setHuntData] = useState(null)

  async function handleSearch(e) {
    e?.preventDefault()
    setLoading(true)
    setEnrichData(null)
    setHuntData(null)
    try {
      const params = { q: query, page_size: 25 }
      if (filters.type) params.type = filters.type
      if (filters.source) params.source = filters.source
      if (filters.severity) params.severity = filters.severity
      if (filters.minScore) params.min_score = filters.minScore
      const res = await axiosClient.get('/search', { params })
      setResults(res.data)
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function handleEnrich(indicator) {
    try {
      const res = await axiosClient.get(`/search/enrich/${encodeURIComponent(indicator)}`)
      setEnrichData(res.data)
    } catch {
      setEnrichData(null)
    }
  }

  async function handleHunt(indicator) {
    try {
      const res = await axiosClient.get(`/hunt/similar/${encodeURIComponent(indicator)}`)
      setHuntData(res.data)
    } catch {
      setHuntData(null)
    }
  }

  const sevColors = {
    critical: 'bg-red-100 text-red-700 border-red-200',
    high: 'bg-orange-100 text-orange-700 border-orange-200',
    medium: 'bg-amber-100 text-amber-700 border-amber-200',
    low: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  }

  return (
    <div className="space-y-6">
      {/* Search Bar */}
      <div className="card">
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <svg className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search IOCs... (IP, domain, hash, or keyword)"
                className="input pl-12 text-base py-3.5"
              />
            </div>
            <button type="submit" disabled={loading} className="btn btn-primary px-8">
              {loading ? 'Searching...' : 'Search'}
            </button>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <select value={filters.type} onChange={e => setFilters({...filters, type: e.target.value})}
              className="input w-auto py-2">
              <option value="">All Types</option>
              <option value="ipv4">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">Hash</option>
              <option value="email">Email</option>
            </select>
            <select value={filters.severity} onChange={e => setFilters({...filters, severity: e.target.value})}
              className="input w-auto py-2">
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <input type="number" value={filters.minScore} onChange={e => setFilters({...filters, minScore: e.target.value})}
              placeholder="Min Score" className="input w-28 py-2" min="0" max="100" />
          </div>
        </form>
      </div>

      {/* Results Aggregations */}
      {results?.aggregations && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.entries(results.aggregations.by_severity || {}).map(([sev, count]) => (
            <div key={sev} className={`p-3 rounded-xl border ${sevColors[sev] || 'bg-slate-50'}`}>
              <div className="text-lg font-bold">{count}</div>
              <div className="text-xs capitalize">{sev}</div>
            </div>
          ))}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
            <div className="text-lg font-bold">{results?.total || 0}</div>
            <div className="text-xs text-slate-500">Total Results</div>
          </div>
        </div>
      )}

      {/* Results Table */}
      {results?.results?.length > 0 && (
        <div className="card">
          <h3 className="text-base font-semibold mb-4">Search Results</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="table-header">
                  <th className="px-4 py-3 rounded-l-lg">Indicator</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3 rounded-r-lg">Actions</th>
                </tr>
              </thead>
              <tbody>
                {results.results.map((item, i) => (
                  <tr key={i} className="table-row">
                    <td className="px-4 py-3 font-mono text-sm max-w-[250px] truncate">{item.indicator}</td>
                    <td className="px-4 py-3"><span className="badge badge-neutral">{item.type}</span></td>
                    <td className="px-4 py-3 text-xs text-slate-600">{item.source}</td>
                    <td className="px-4 py-3">
                      <span className={`badge ${sevColors[item.severity] || 'badge-neutral'}`}>{item.severity}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm font-bold">{item.confidence_score ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        <button onClick={() => handleEnrich(item.indicator)}
                          className="text-xs text-accent hover:underline">Enrich</button>
                        <span className="text-slate-300">|</span>
                        <button onClick={() => handleHunt(item.indicator)}
                          className="text-xs text-purple-600 hover:underline">Hunt</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Enrichment Panel */}
      {enrichData && (
        <div className="card border-l-4 border-l-accent">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">Enrichment: {enrichData.indicator}</h3>
            <button onClick={() => setEnrichData(null)} className="text-slate-400 hover:text-slate-600">✕</button>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <div className="text-xs text-slate-500 mb-1">Sources</div>
              <div className="flex flex-wrap gap-1">
                {enrichData.all_sources?.map(s => (
                  <span key={s} className="badge badge-info">{s}</span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Threat Types</div>
              <div className="flex flex-wrap gap-1">
                {enrichData.threat_types?.map(t => (
                  <span key={t} className="badge badge-warning">{t}</span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Score</div>
              <div className="text-2xl font-bold">{enrichData.confidence_score ?? '—'}</div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Geo</div>
              <div>{enrichData.geo?.country || 'Unknown'} {enrichData.geo?.city ? `, ${enrichData.geo.city}` : ''}</div>
            </div>
          </div>
          {enrichData.metadata?.virustotal && (
            <div className="mt-3 p-3 bg-slate-50 rounded-lg">
              <div className="text-xs font-medium text-slate-600">VirusTotal</div>
              <div className="text-sm mt-1">
                Detections: {enrichData.metadata.virustotal.vt_score ?? 'N/A'} | 
                Last Analysis: {enrichData.metadata.virustotal.vt_last_analysis || 'N/A'}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Threat Hunt Panel */}
      {huntData && (
        <div className="card border-l-4 border-l-purple-500">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">🔍 Threat Hunt: Similar to {huntData.query_indicator}</h3>
            <button onClick={() => setHuntData(null)} className="text-slate-400 hover:text-slate-600">✕</button>
          </div>
          <div className="text-sm text-slate-500 mb-3">{huntData.total} similar indicators found</div>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {huntData.similar?.map((item, i) => (
              <div key={i} className="flex items-center justify-between p-2.5 bg-slate-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className={`badge ${sevColors[item.severity] || 'badge-neutral'}`}>{item.severity}</span>
                  <span className="font-mono text-sm">{item.indicator}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500">{item.source}</span>
                  <span className="text-sm font-bold">{item.confidence_score}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {results && results.results?.length === 0 && !loading && (
        <div className="text-center py-12 text-slate-400">
          <div className="text-4xl mb-3">🔍</div>
          <div className="text-sm">No results found for "{query}"</div>
        </div>
      )}
    </div>
  )
}
