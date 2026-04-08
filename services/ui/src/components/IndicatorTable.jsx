export default function IndicatorTable({ indicators }) {
  const typeConfig = {
    ipv4: { color: 'bg-accent-50 text-accent-dark', icon: '🌐' },
    ipv6: { color: 'bg-accent-50 text-accent-dark', icon: '🌐' },
    domain: { color: 'bg-purple-50 text-purple-700', icon: '🏠' },
    url: { color: 'bg-warning/10 text-warning', icon: '🔗' },
    hash: { color: 'bg-danger/10 text-danger', icon: '🔐' },
    email: { color: 'bg-success/10 text-success', icon: '📧' },
    cve: { color: 'bg-orange-50 text-orange-700', icon: '🐛' },
  }

  function getScoreColor(score) {
    if (score >= 70) return 'text-danger bg-danger/10'
    if (score >= 40) return 'text-warning bg-warning/10'
    return 'text-success bg-success/10'
  }

  function getScoreBar(score) {
    const width = Math.min(100, Math.max(5, score || 0))
    const color = score >= 70 ? 'bg-danger' : score >= 40 ? 'bg-warning' : 'bg-success'
    return (
      <div className="w-16 h-1.5 bg-primary-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all duration-500`} style={{ width: `${width}%` }}></div>
      </div>
    )
  }

  if (indicators.length === 0) {
    return (
      <div className="text-center py-12 text-primary-400">
        <span className="material-symbols-outlined text-5xl mb-3">search</span>
        <div className="text-sm font-semibold text-primary-600">No indicators found</div>
        <div className="text-xs mt-1 text-primary-400">Trigger a feed sync to start seeing data</div>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto -mx-6 px-6">
      <table className="min-w-full">
        <thead>
          <tr className="table-header">
            <th className="px-4 py-3 rounded-l-lg">Indicator</th>
            <th className="px-4 py-3">Type</th>
            <th className="px-4 py-3">Source</th>
            <th className="px-4 py-3">Score</th>
            <th className="px-4 py-3 rounded-r-lg">Geo</th>
          </tr>
        </thead>
        <tbody>
          {indicators.map((item) => {
            const tc = typeConfig[item.type] || { color: 'bg-primary-100 text-primary-600', icon: '📌' }
            return (
              <tr key={`${item.source}-${item.indicator}`} className="table-row animate-fade-in">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className="text-base">{tc.icon}</span>
                    <span className="font-mono text-sm text-primary-800 max-w-[200px] truncate" title={item.indicator}>
                      {item.indicator}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`badge ${tc.color}`}>{item.type}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-semibold text-primary-600 bg-primary-50 px-2.5 py-1 rounded-lg">
                    {item.source}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold px-2 py-0.5 rounded-lg ${getScoreColor(item.confidence_score)}`}>
                      {item.confidence_score ?? '—'}
                    </span>
                    {getScoreBar(item.confidence_score)}
                  </div>
                </td>
                <td className="px-4 py-3">
                  {item.geo?.country ? (
                    <span className="text-xs text-primary-500">{item.geo.country}</span>
                  ) : (
                    <span className="text-xs text-primary-300">—</span>
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