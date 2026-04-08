import { useState } from 'react'

export default function AIPanel({ axiosClient }) {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)

  async function loadAnalysis() {
    setLoading(true)
    try {
      const res = await axiosClient.get('/stats/advanced')
      setStats(res.data)
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  if (!stats && !loading) {
    return (
      <div className="card text-center py-8">
        <div className="text-3xl mb-3">🤖</div>
        <h3 className="text-lg font-semibold mb-2">AI Threat Analysis</h3>
        <p className="text-sm text-slate-500 mb-4">Generate intelligent analysis of your threat landscape</p>
        <button onClick={loadAnalysis} className="btn btn-primary">Generate Analysis</button>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="card text-center py-8">
        <div className="inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mb-3"></div>
        <div className="text-sm text-slate-500">Analyzing threat data...</div>
      </div>
    )
  }

  if (!stats) return null

  // Generate AI-like summary
  const topThreats = Object.entries(stats.by_threat_type || {}).sort((a, b) => b[1] - a[1]).slice(0, 5)
  const topCountries = Object.entries(stats.by_country || {}).sort((a, b) => b[1] - a[1]).slice(0, 5)
  const criticalCount = stats.by_severity?.critical || 0
  const highCount = stats.by_severity?.high || 0
  const avgScore = Math.round(stats.score_avg || 0)

  return (
    <div className="space-y-6">
      {/* Summary Card */}
      <div className="card-gradient">
        <div className="flex items-center gap-2 mb-4">
          <span className="text-xl">🤖</span>
          <h3 className="text-lg font-bold">AI Threat Summary</h3>
        </div>
        <div className="text-sm text-slate-300 leading-relaxed space-y-2">
          <p>
            Analysis of <span className="text-white font-semibold">{stats.total_indicators}</span> indicators 
            across <span className="text-white font-semibold">{Object.keys(stats.by_source || {}).length}</span> intelligence sources.
          </p>
          <p>
            Average confidence score: <span className="text-white font-semibold">{avgScore}/100</span>
            {avgScore >= 60 && ' — Elevated threat landscape'}
            {avgScore >= 40 && avgScore < 60 && ' — Moderate threat level'}
            {avgScore < 40 && ' — Baseline threat level'}
          </p>
          {(criticalCount > 0 || highCount > 0) && (
            <p className="text-red-300">
              ⚠️ <span className="font-semibold">{criticalCount}</span> critical and <span className="font-semibold">{highCount}</span> high severity indicators require immediate attention.
            </p>
          )}
        </div>
      </div>

      {/* Threat Breakdown */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className="card">
          <h4 className="text-sm font-semibold text-slate-600 mb-3">🎯 Top Threat Types</h4>
          <div className="space-y-2">
            {topThreats.map(([type, count]) => {
              const pct = Math.round((count / stats.total_indicators) * 100)
              return (
                <div key={type} className="flex items-center gap-3">
                  <div className="w-24 text-xs text-slate-600 truncate">{type}</div>
                  <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-accent rounded-full transition-all" style={{ width: `${pct}%` }}></div>
                  </div>
                  <div className="text-xs font-bold text-slate-700 w-12 text-right">{count}</div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="card">
          <h4 className="text-sm font-semibold text-slate-600 mb-3">🌍 Top Affected Countries</h4>
          <div className="space-y-2">
            {topCountries.map(([country, count]) => {
              const pct = Math.round((count / stats.total_indicators) * 100)
              return (
                <div key={country} className="flex items-center gap-3">
                  <div className="w-24 text-xs text-slate-600 truncate">{country}</div>
                  <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-purple-500 rounded-full transition-all" style={{ width: `${pct}%` }}></div>
                  </div>
                  <div className="text-xs font-bold text-slate-700 w-12 text-right">{count}</div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Severity Distribution */}
      <div className="card">
        <h4 className="text-sm font-semibold text-slate-600 mb-3">📊 Severity Distribution</h4>
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Critical', key: 'critical', color: 'bg-red-500', textColor: 'text-red-600' },
            { label: 'High', key: 'high', color: 'bg-orange-500', textColor: 'text-orange-600' },
            { label: 'Medium', key: 'medium', color: 'bg-amber-500', textColor: 'text-amber-600' },
            { label: 'Low', key: 'low', color: 'bg-emerald-500', textColor: 'text-emerald-600' },
          ].map(({ label, key, color, textColor }) => (
            <div key={key} className="text-center p-4 rounded-xl bg-slate-50">
              <div className={`text-2xl font-bold ${textColor}`}>{stats.by_severity?.[key] || 0}</div>
              <div className="text-xs text-slate-500 mt-1">{label}</div>
              <div className={`h-1 ${color} rounded-full mt-2 mx-auto w-8`}></div>
            </div>
          ))}
        </div>
      </div>

      {/* Recommendations */}
      <div className="card">
        <h4 className="text-sm font-semibold text-slate-600 mb-3">💡 Recommendations</h4>
        <div className="space-y-2">
          {criticalCount > 0 && (
            <div className="flex items-start gap-2 p-3 bg-red-50 rounded-lg border border-red-200">
              <span className="text-red-500">🔴</span>
              <div className="text-sm text-red-700">
                <span className="font-semibold">{criticalCount} critical indicators</span> — Block immediately and create incident tickets.
              </div>
            </div>
          )}
          {highCount > 5 && (
            <div className="flex items-start gap-2 p-3 bg-orange-50 rounded-lg border border-orange-200">
              <span className="text-orange-500">🟠</span>
              <div className="text-sm text-orange-700">
                <span className="font-semibold">{highCount} high severity indicators</span> — Review and add to SIEM watchlist.
              </div>
            </div>
          )}
          <div className="flex items-start gap-2 p-3 bg-blue-50 rounded-lg border border-blue-200">
            <span className="text-blue-500">🔵</span>
            <div className="text-sm text-blue-700">
              Run threat hunting queries against Zeek and Suricata logs for indicators above score 60.
            </div>
          </div>
          <div className="flex items-start gap-2 p-3 bg-emerald-50 rounded-lg border border-emerald-200">
            <span className="text-emerald-500">🟢</span>
            <div className="text-sm text-emerald-700">
              Export firewall blocklist for all critical and high severity IPs.
            </div>
          </div>
        </div>
      </div>

      <button onClick={loadAnalysis} className="btn btn-outline text-sm">
        🔄 Refresh Analysis
      </button>
    </div>
  )
}
