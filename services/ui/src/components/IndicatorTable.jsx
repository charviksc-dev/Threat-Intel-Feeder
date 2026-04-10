export default function IndicatorTable({ indicators, selectedIds = [], onSelect }) {
  const typeConfig = {
    ipv4: { bg: 'bg-sky-500/10', text: 'text-sky-600', icon: 'hub' },
    ipv6: { bg: 'bg-sky-500/10', text: 'text-sky-600', icon: 'hub' },
    domain: { bg: 'bg-indigo-500/10', text: 'text-indigo-600', icon: 'language' },
    hostname: { bg: 'bg-violet-500/10', text: 'text-violet-600', icon: 'dns' },
    url: { bg: 'bg-amber-500/10', text: 'text-amber-600', icon: 'link' },
    hash: { bg: 'bg-rose-500/10', text: 'text-rose-600', icon: 'fingerprint' },
    email: { bg: 'bg-emerald-500/10', text: 'text-emerald-600', icon: 'mail' },
    cve: { bg: 'bg-orange-500/10', text: 'text-orange-600', icon: 'pest_control' },
  }

  function toggleSelect(id) {
    if (selectedIds.includes(id)) {
      onSelect(selectedIds.filter(i => i !== id))
    } else {
      onSelect([...selectedIds, id])
    }
  }

  function toggleAll() {
    if (selectedIds.length === indicators.length) {
      onSelect([])
    } else {
      onSelect(indicators.map(i => i.id || `${i.source}::${i.indicator}`))
    }
  }

  function getScoreColor(score) {
    if (score >= 70) return 'text-rose-600 bg-rose-500/10'
    if (score >= 40) return 'text-amber-600 bg-amber-500/10'
    return 'text-emerald-600 bg-emerald-500/10'
  }

  function getScoreBar(score) {
    const width = Math.min(100, Math.max(5, score || 0))
    const color = score >= 70 ? 'bg-rose-500' : score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
    return (
      <div className="w-16 h-1.5 bg-slate-100 rounded-full overflow-hidden shadow-inner">
        <div className={`h-full rounded-full ${color} transition-all duration-700 ease-out shadow-lg`} style={{ width: `${width}%` }}></div>
      </div>
    )
  }

  if (indicators.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-300">
        <div className="w-20 h-20 rounded-full bg-slate-50 flex items-center justify-center mb-6 border border-slate-100 shadow-inner group">
          <span className="material-symbols-outlined text-4xl group-hover:scale-110 transition-transform">database_off</span>
        </div>
        <div className="text-xs font-black uppercase tracking-[0.2em] text-slate-400">Zero Observables</div>
        <p className="text-[10px] font-bold mt-2 opacity-60">Initialize feed synchronization to populate hub</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto custom-scrollbar">
      <table className="min-w-full border-separate border-spacing-y-2">
        <thead>
          <tr className="text-[10px] font-black text-slate-400 uppercase tracking-widest">
            <th className="px-4 py-4 text-center">
              <input type="checkbox" checked={selectedIds.length === indicators.length && indicators.length > 0} onChange={toggleAll} className="w-4 h-4 rounded border-slate-200" />
            </th>
            <th className="px-6 py-4 text-left font-black">Observable Identifier</th>
            <th className="px-6 py-4 text-left font-black">Protocol</th>
            <th className="px-6 py-4 text-left font-black">Authority</th>
            <th className="px-6 py-4 text-left font-black">Threat Level</th>
            <th className="px-6 py-4 text-left font-black">Node Origin</th>
            <th className="px-6 py-4 text-left font-black">Sources</th>
          </tr>
        </thead>
        <tbody className="divide-y-0 text-sm">
          {indicators.map((item, idx) => {
            const tc = typeConfig[item.type] || { bg: 'bg-slate-500/10', text: 'text-slate-600', icon: 'label' }
            const itemId = item.id || `${item.source}::${item.indicator}`
            const isSelected = selectedIds.includes(itemId)
            
            return (
              <tr 
                key={`${item.source}-${item.indicator}-${idx}`} 
                className={`group hover:bg-slate-50 transition-all duration-300 animate-slide-up ${isSelected ? 'bg-sky-50/50' : ''}`}
                style={{ animationDelay: `${idx * 0.02}s` }}
              >
                <td className="px-4 py-4 bg-white first:rounded-l-2xl border-y border-l border-slate-100 text-center">
                  <input type="checkbox" checked={isSelected} onChange={() => toggleSelect(itemId)} className="w-4 h-4 rounded border-slate-200" />
                </td>
                <td className="px-6 py-4 bg-white group-hover:bg-sky-50 transition-colors duration-300 border-y border-slate-100 group-hover:border-sky-100">
                  <div className="flex items-center gap-4">
                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${tc.bg} ${tc.text} transition-transform group-hover:scale-110 border border-white/50 shadow-sm`}>
                      <span className="material-symbols-outlined text-[18px]">{tc.icon}</span>
                    </div>
                    <span className="font-mono text-xs font-black text-slate-800 max-w-[240px] truncate tracking-tight" title={item.indicator}>
                      {item.indicator}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 bg-white group-hover:bg-sky-50 transition-colors duration-300 border-y border-slate-100 group-hover:border-sky-100">
                  <span className={`text-[9px] font-black px-2.5 py-1 rounded-lg uppercase tracking-widest border border-black/5 ${tc.bg} ${tc.text}`}>
                    {item.type}
                  </span>
                </td>
                <td className="px-6 py-4 bg-white group-hover:bg-sky-50 transition-colors duration-300 border-y border-slate-100 group-hover:border-sky-100">
                  <span className="text-[10px] font-bold text-slate-500 bg-slate-100 px-3 py-1.5 rounded-xl border border-white transition-colors group-hover:bg-white">
                    {item.source}
                  </span>
                  {item.seen_in_sources > 1 && (
                    <span className="ml-2 text-[9px] font-black px-1.5 py-0.5 rounded bg-violet-100 text-violet-600" title={`Seen in ${item.seen_in_sources} sources`}>
                      ×{item.seen_in_sources}
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 bg-white group-hover:bg-sky-50 transition-colors duration-300 border-y border-slate-100 group-hover:border-sky-100">
                  <div className="flex items-center gap-3">
                    <div className="flex flex-col gap-1">
                      <span className={`text-[10px] font-black px-2 py-0.5 rounded-md w-fit ${getScoreColor(item.confidence_score)}`}>
                        {item.confidence_score ?? 0}%
                      </span>
                      {getScoreBar(item.confidence_score)}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 bg-white last:rounded-r-2xl group-hover:bg-sky-50 transition-colors duration-300 border-y border-r border-slate-100 group-hover:border-sky-100">
                  {item.geo?.country ? (
                    <div className="flex items-center gap-2">
                       <span className="w-6 h-4 rounded-sm bg-slate-100 flex items-center justify-center text-[10px] font-black text-slate-400">
                         {item.geo.country_code || '??'}
                       </span>
                       <span className="text-[11px] font-bold text-slate-600">{item.geo.country}</span>
                    </div>
                  ) : (
                    <span className="text-[10px] font-black text-slate-300 tracking-[0.1em]">UNAFFILIATED</span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}