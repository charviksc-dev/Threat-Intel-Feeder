import { useState, useEffect, useRef } from 'react'

export default function RealtimeFeed({ axiosClient }) {
  const [alerts, setAlerts] = useState([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const feedRef = useRef(null)

  useEffect(() => {
    loadInitial()
    const interval = setInterval(() => {
      if (!paused) loadInitial()
    }, 5000)
    setConnected(true)
    return () => clearInterval(interval)
  }, [paused])

  async function loadInitial() {
    try {
      const res = await axiosClient.get('/alerts?limit=25')
      const newAlerts = res.data || []
      setAlerts(prev => {
        if (JSON.stringify(newAlerts) !== JSON.stringify(prev)) {
          return newAlerts
        }
        return prev
      })
    } catch (err) {
      console.error(err)
    }
  }

  const [expandedId, setExpandedId] = useState(null)

  const severityConfig = {
    critical: { bg: 'bg-rose-500/10', text: 'text-rose-600', border: 'border-rose-500/20', dot: 'bg-rose-500' },
    high: { bg: 'bg-orange-500/10', text: 'text-orange-600', border: 'border-orange-500/20', dot: 'bg-orange-500' },
    medium: { bg: 'bg-amber-500/10', text: 'text-amber-600', border: 'border-amber-500/20', dot: 'bg-amber-500' },
    low: { bg: 'bg-sky-500/10', text: 'text-sky-600', border: 'border-sky-500/20', dot: 'bg-sky-500' },
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between bg-white p-4 rounded-2xl border border-slate-100 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5 px-3 py-1.5 bg-slate-50 rounded-full border border-slate-100">
            <div className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)] animate-pulse' : 'bg-rose-500'}`}></div>
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-600">{connected ? 'Live Sync Active' : 'Offline'}</span>
          </div>
          <span className="text-xs font-bold text-slate-400">{alerts.length} Observables in buffer</span>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setPaused(!paused)}
            className={`btn-primary px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${paused ? 'bg-amber-500 text-white' : 'bg-slate-900 text-white'}`}>
            {paused ? '▶ Resume' : '⏸ Pause Feed'}
          </button>
          <button onClick={loadInitial} className="p-2 rounded-xl bg-slate-50 text-slate-400 hover:bg-white hover:text-sky-500 border border-transparent hover:border-slate-100 transition-all">
            <span className="material-symbols-outlined text-[18px]">refresh</span>
          </button>
        </div>
      </div>

      <div ref={feedRef} className="space-y-3 max-h-[580px] overflow-y-auto pr-2 custom-scrollbar">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-300">
            <div className="w-20 h-20 rounded-3xl bg-slate-50 flex items-center justify-center mb-6 border border-slate-100 shadow-inner">
               <span className="material-symbols-outlined text-4xl">notifications_active</span>
            </div>
            <div className="text-xs font-black uppercase tracking-widest">No Active Threats</div>
            <div className="text-[10px] font-bold mt-2 opacity-60">Ready for incoming telemetry</div>
          </div>
        ) : (
          alerts.map((alert, idx) => {
            const sev = severityConfig[alert.severity] || severityConfig.medium
            const isExpanded = expandedId === alert.alert_id
            
            return (
              <div key={alert.alert_id || idx} 
                className={`group p-4 rounded-2xl bg-white border border-slate-100 transition-all duration-300 hover:shadow-xl hover:shadow-slate-200/50 hover:-translate-y-0.5 cursor-pointer animate-slide-up`}
                style={{ animationDelay: `${idx * 0.03}s` }}
                onClick={() => setExpandedId(isExpanded ? null : alert.alert_id)}
              >
                <div className="flex items-start gap-4">
                  <div className={`w-1 h-12 rounded-full ${sev.dot} shrink-0 opacity-80 group-hover:scale-y-110 transition-transform`}></div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-black text-slate-900 uppercase tracking-tight truncate">
                        {alert.category || alert.source || 'Threat Event'}
                      </span>
                      <div className="flex items-center gap-3">
                        <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-lg border ${sev.border} ${sev.text} ${sev.bg} tracking-widest`}>
                          {alert.severity || 'medium'}
                        </span>
                        <span className={`material-symbols-outlined text-[16px] text-slate-300 transition-transform duration-300 ${isExpanded ? 'rotate-180 text-sky-500' : ''}`}>
                          expand_more
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 mt-1.5 font-mono text-[10px] font-bold text-slate-400">
                      <span className="px-1.5 py-0.5 bg-slate-50 rounded border border-slate-100 text-slate-600 uppercase">SRC: {alert.source}</span>
                      <span className="truncate">UID: {alert.alert_id}</span>
                    </div>
                    
                    {alert.payload?.rule?.description && !isExpanded && (
                      <p className="text-[11px] font-bold text-slate-500 mt-2 line-clamp-1">{alert.payload.rule.description}</p>
                    )}
                    
                    {isExpanded && (
                      <div className="mt-4 animate-fade-in" onClick={(e) => e.stopPropagation()}>
                        <div className="relative group/json">
                          <div className="absolute right-3 top-3 flex gap-2">
                             <button 
                                className="px-2 py-1 rounded bg-black/5 hover:bg-black/10 text-[9px] font-black uppercase tracking-widest text-slate-600 transition-colors"
                                onClick={() => navigator.clipboard.writeText(JSON.stringify(alert.payload, null, 2))}
                              >
                                Copy Buffer
                              </button>
                          </div>
                          <pre className="p-5 bg-slate-900 rounded-2xl text-[10px] text-sky-400/90 leading-relaxed font-mono overflow-x-auto shadow-2xl border border-white/5 custom-scrollbar bg-gradient-to-br from-slate-900 to-black">
                            {JSON.stringify(alert.payload, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                    
                    <div className="mt-4 pt-3 border-t border-slate-50 flex items-center justify-between">
                      <div className="flex items-center gap-1.5 text-[9px] font-black text-slate-400 uppercase tracking-widest">
                        <span className="material-symbols-outlined text-[14px]">schedule</span>
                        {alert.received_at ? new Date(alert.received_at).toLocaleTimeString() : ''}
                      </div>
                      <span className="text-[9px] font-black text-sky-500 opacity-0 group-hover:opacity-100 transition-opacity">Protocol Action Required</span>
                    </div>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>

      <div className="grid grid-cols-4 gap-3">
        {['critical', 'high', 'medium', 'low'].map(sev => {
          const count = alerts.filter(a => a.severity === sev).length
          const sevConf = severityConfig[sev]
          return (
            <div key={sev} className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm relative overflow-hidden group hover:shadow-md transition-shadow">
              <div className={`absolute left-0 top-0 bottom-0 w-1 ${sevConf.dot} opacity-40`}></div>
              <div className={`text-xl font-black text-slate-900 tracking-tighter`}>{count}</div>
              <div className="text-[9px] font-black text-slate-400 uppercase tracking-widest mt-1">{sev} Impact</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
