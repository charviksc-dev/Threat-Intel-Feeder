import { useState, useEffect, useRef } from 'react'

export default function RealtimeFeed({ axiosClient }) {
  const [alerts, setAlerts] = useState([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const feedRef = useRef(null)

  useEffect(() => {
    loadInitial()
    // Poll for new alerts every 5 seconds
    const interval = setInterval(() => {
      if (!paused) loadInitial()
    }, 5000)
    setConnected(true)
    return () => clearInterval(interval)
  }, [paused])

  async function loadInitial() {
    try {
      // Fetch from API alerts endpoint
      const res = await axiosClient.get('/alerts?limit=20')
      const newAlerts = res.data || []
      setAlerts(prev => {
        // Only update if different
        if (JSON.stringify(newAlerts) !== JSON.stringify(prev)) {
          return newAlerts
        }
        return prev
      })
    } catch (err) {
      console.error(err)
    }
  }

  const severityConfig = {
    critical: { color: 'bg-red-500', border: 'border-red-200 bg-red-50', text: 'text-red-700' },
    high: { color: 'bg-orange-500', border: 'border-orange-200 bg-orange-50', text: 'text-orange-700' },
    medium: { color: 'bg-amber-500', border: 'border-amber-200 bg-amber-50', text: 'text-amber-700' },
    low: { color: 'bg-blue-500', border: 'border-blue-200 bg-blue-50', text: 'text-blue-700' },
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></div>
            <span className="text-sm font-medium">{connected ? 'Live' : 'Disconnected'}</span>
          </div>
          <span className="text-xs text-slate-400">{alerts.length} alerts</span>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setPaused(!paused)}
            className={`btn text-xs ${paused ? 'btn-primary' : 'btn-ghost'}`}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button onClick={loadInitial} className="btn btn-ghost text-xs">↻ Refresh</button>
        </div>
      </div>

      {/* Alert Feed */}
      <div ref={feedRef} className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
        {alerts.length === 0 ? (
          <div className="text-center py-12 text-slate-400">
            <div className="text-3xl mb-2">🔔</div>
            <div className="text-sm">No alerts yet. Alerts appear when threats are detected.</div>
          </div>
        ) : (
          alerts.map((alert, i) => {
            const sev = severityConfig[alert.severity] || severityConfig.medium
            return (
              <div key={alert.alert_id || i} className={`p-3.5 rounded-xl border ${sev.border} transition-all duration-200 hover:shadow-sm`}>
                <div className="flex items-start gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${sev.color} mt-1.5 shrink-0`}></div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-slate-800 truncate">
                        {alert.category || alert.source || 'Alert'}
                      </span>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${sev.text}`}>
                        {alert.severity || 'medium'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 truncate">
                      Source: {alert.source} | ID: {alert.alert_id?.substring(0, 20)}
                    </p>
                    {alert.payload?.rule?.description && (
                      <p className="text-xs text-slate-600 mt-1">{alert.payload.rule.description}</p>
                    )}
                    <p className="text-[10px] text-slate-400 mt-1">
                      {alert.received_at ? new Date(alert.received_at).toLocaleString() : ''}
                    </p>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-2">
        {['critical', 'high', 'medium', 'low'].map(sev => {
          const count = alerts.filter(a => a.severity === sev).length
          const sevConf = severityConfig[sev]
          return (
            <div key={sev} className="p-2.5 rounded-lg bg-slate-50 text-center">
              <div className={`text-lg font-bold ${sevConf.text}`}>{count}</div>
              <div className="text-[10px] text-slate-400 capitalize">{sev}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
