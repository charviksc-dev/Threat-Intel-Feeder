import { useEffect, useState } from 'react'

export default function IOCConflictResolution({ axiosClient }) {
  const [conflicts, setConflicts] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedConflict, setSelectedConflict] = useState(null)
  const [resolving, setResolving] = useState(false)

  useEffect(() => {
    fetchConflicts()
  }, [])

  async function fetchConflicts() {
    try {
      const res = await axiosClient.get('/indicators/conflicts')
      setConflicts(res.data)
    } catch (err) {
      console.error('Failed to fetch conflicts', err)
      setConflicts([])
    } finally {
      setLoading(false)
    }
  }

  async function resolveConflict(indicator, selectedSource, resolution) {
    setResolving(true)
    try {
      await axiosClient.post('/indicators/conflicts/resolve', {
        indicator,
        selected_source: selectedSource,
        resolution,
      })
      fetchConflicts()
      setSelectedConflict(null)
    } catch (err) {
      console.error('Failed to resolve conflict', err)
    } finally {
      setResolving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
      </div>
    )
  }

  if (conflicts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-300">
        <div className="w-20 h-20 rounded-full bg-emerald-50 flex items-center justify-center mb-6 border border-emerald-100 shadow-inner">
          <span className="material-symbols-outlined text-4xl text-emerald-500">check_circle</span>
        </div>
        <div className="text-xs font-black uppercase tracking-[0.2em] text-slate-400">No Conflicts Detected</div>
        <p className="text-[10px] font-bold mt-2 opacity-60">All IOCs are properly deduplicated</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-center gap-3">
        <span className="material-symbols-outlined text-amber-600">warning</span>
        <div>
          <p className="text-sm font-bold text-amber-800">{conflicts.length} IOC Conflict{conflicts.length > 1 ? 's' : ''} Detected</p>
          <p className="text-xs text-amber-600">Same IOC reported from multiple feeds with different threat scores</p>
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full border-separate border-spacing-y-0">
            <thead>
              <tr className="text-[10px] font-black text-slate-400 uppercase tracking-widest bg-slate-50">
                <th className="px-6 py-4 text-left">IOC Value</th>
                <th className="px-6 py-4 text-left">Type</th>
                <th className="px-6 py-4 text-center">Sources</th>
                <th className="px-6 py-4 text-center">Score Range</th>
                <th className="px-6 py-4 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {conflicts.map((conflict, idx) => (
                <tr key={`${conflict.indicator}-${idx}`} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-4">
                    <span className="font-mono text-xs font-bold text-slate-800 bg-slate-100 px-3 py-1.5 rounded-lg">
                      {conflict.indicator}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-[10px] font-black px-2.5 py-1 rounded-lg uppercase tracking-widest bg-sky-500/10 text-sky-600 border border-sky-200">
                      {conflict.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-center">
                    <div className="flex items-center justify-center gap-1">
                      {conflict.sources.map((src, i) => (
                        <span key={i} className="w-6 h-6 rounded-full bg-slate-200 text-[9px] font-bold text-slate-600 flex items-center justify-center">
                          {src.charAt(0).toUpperCase()}
                        </span>
                      ))}
                      <span className="ml-1 text-xs font-bold text-slate-500">×{conflict.sources.length}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-600">
                        {conflict.min_score}%
                      </span>
                      <span className="text-slate-300">→</span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-200 text-rose-700">
                        {conflict.max_score}%
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => setSelectedConflict(conflict)}
                      className="px-4 py-2 rounded-xl text-xs font-bold bg-slate-900 text-white hover:bg-slate-700 transition-all"
                    >
                      Resolve
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedConflict && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm" onClick={() => setSelectedConflict(null)}></div>
          <div className="relative bg-white rounded-2xl shadow-2xl max-w-lg w-full p-6 animate-fade-in">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-slate-900">Resolve Conflict</h3>
              <button onClick={() => setSelectedConflict(null)} className="p-2 rounded-xl hover:bg-slate-100">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <div className="mb-6">
              <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">IOC Value</div>
              <div className="font-mono text-sm font-bold text-slate-800 bg-slate-100 px-4 py-3 rounded-xl">
                {selectedConflict.indicator}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Select Preferred Source</div>
              <div className="space-y-2">
                {selectedConflict.source_details.map((src, idx) => (
                  <label
                    key={idx}
                    className="flex items-center gap-4 p-4 rounded-xl border border-slate-200 hover:border-sky-300 hover:bg-sky-50/50 cursor-pointer transition-all"
                  >
                    <input type="radio" name="source" value={src.source} className="w-4 h-4 text-sky-600" />
                    <div className="flex-1">
                      <div className="text-sm font-bold text-slate-800">{src.source}</div>
                      <div className="text-xs text-slate-500">Confidence: {src.confidence_score}% | Seen: {src.seen_count} time{src.seen_count > 1 ? 's' : ''}</div>
                    </div>
                    <div className={`text-[10px] font-black px-2 py-1 rounded ${
                      src.confidence_score >= 70 ? 'bg-rose-100 text-rose-600' :
                      src.confidence_score >= 40 ? 'bg-amber-100 text-amber-600' : 'bg-emerald-100 text-emerald-600'
                    }`}>
                      {src.confidence_score}%
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="mb-6">
              <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Resolution Strategy</div>
              <select id="resolution" className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-sky-500/20">
                <option value="highest_score">Use Highest Score</option>
                <option value="most_sources">Most Sources (Consensus)</option>
                <option value="selected_source">Use Selected Source Only</option>
                <option value="average">Average Score</option>
              </select>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setSelectedConflict(null)}
                className="flex-1 px-4 py-3 rounded-xl text-sm font-bold text-slate-600 bg-slate-100 hover:bg-slate-200 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={() => resolveConflict(
                  selectedConflict.indicator,
                  document.querySelector('input[name="source"]:checked')?.value,
                  document.getElementById('resolution').value
                )}
                disabled={resolving || !document.querySelector('input[name="source"]:checked')}
                className="flex-1 px-4 py-3 rounded-xl text-sm font-bold bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {resolving ? 'Resolving...' : 'Apply Resolution'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}