export default function AlertsPanel({ alerts }) {
  const severityConfig = {
    critical: { bg: 'bg-rose-500/10', text: 'text-rose-600', border: 'border-rose-500/20', dot: 'bg-rose-500', glow: 'shadow-rose-500/20' },
    high: { bg: 'bg-orange-500/10', text: 'text-orange-600', border: 'border-orange-500/20', dot: 'bg-orange-500', glow: 'shadow-orange-500/20' },
    medium: { bg: 'bg-amber-500/10', text: 'text-amber-600', border: 'border-amber-500/20', dot: 'bg-amber-500', glow: 'shadow-amber-500/20' },
    low: { bg: 'bg-sky-500/10', text: 'text-sky-600', border: 'border-sky-500/20', dot: 'bg-sky-500', glow: 'shadow-sky-500/20' },
  }

  if (alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-slate-300">
        <div className="w-16 h-16 rounded-3xl bg-slate-50 flex items-center justify-center mb-4 border border-slate-100 shadow-inner">
          <span className="material-symbols-outlined text-3xl">notifications_off</span>
        </div>
        <div className="text-xs font-black uppercase tracking-widest">Clear Perimeter</div>
        <div className="text-[10px] font-bold mt-1 opacity-60">No recent alerts detected</div>
      </div>
    )
  }

  return (
    <div className="space-y-3 max-h-[340px] overflow-y-auto pr-2 custom-scrollbar">
      {alerts.slice(0, 10).map((alert, idx) => {
        const sev = severityConfig[alert.severity] || severityConfig.medium
        return (
          <div 
            key={alert.alert_id} 
            className={`flex items-start gap-4 p-4 rounded-2xl bg-white border ${sev.border} transition-all duration-300 hover:shadow-xl hover:shadow-slate-200/50 hover:-translate-y-0.5 group animate-slide-up`}
            style={{ animationDelay: `${idx * 0.05}s` }}
          >
            <div className={`w-2 h-10 rounded-full ${sev.dot} shrink-0 ${sev.glow} shadow-lg transition-transform group-hover:scale-y-110`}></div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-black text-slate-900 uppercase tracking-tight truncate">{alert.source || 'Unknown Source'}</span>
                <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-lg tracking-widest border ${sev.border} ${sev.text} ${sev.bg}`}>
                  {alert.severity || 'medium'}
                </span>
              </div>
              <p className="mt-1 text-[11px] font-bold text-slate-500 truncate">{alert.category || 'Threat landscape event'}</p>
              <div className="mt-2 flex items-center justify-between">
                <span className="text-[9px] font-black text-slate-400 font-mono">{new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                <span className="material-symbols-outlined text-[14px] text-slate-300 group-hover:text-sky-500 transition-colors">arrow_forward_ios</span>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}