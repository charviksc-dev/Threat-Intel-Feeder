export default function AlertsPanel({ alerts }) {
  const severityConfig = {
    critical: { bg: 'bg-danger/10', text: 'text-danger', border: 'border-danger/20', dot: 'bg-danger' },
    high: { bg: 'bg-orange-50 text-orange-700', text: 'text-orange-700', border: 'border-orange-200', dot: 'bg-orange-500' },
    medium: { bg: 'bg-warning/10', text: 'text-warning', border: 'border-warning/20', dot: 'bg-warning' },
    low: { bg: 'bg-info/10', text: 'text-info', border: 'border-info/20', dot: 'bg-info' },
  }

  if (alerts.length === 0) {
    return (
      <div className="text-center py-8 text-primary-400">
        <span className="material-symbols-outlined text-4xl mb-2">notifications_none</span>
        <div className="text-sm font-medium">No recent alerts</div>
      </div>
    )
  }

  return (
    <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
      {alerts.slice(0, 8).map((alert) => {
        const sev = severityConfig[alert.severity] || severityConfig.medium
        return (
          <div key={alert.alert_id} className={`flex items-start gap-3 p-3 rounded-xl ${sev.bg} border ${sev.border} transition-all duration-200 hover:shadow-sm hover:-translate-y-0.5`}>
            <div className={`w-2 h-2 rounded-full ${sev.dot} mt-1.5 shrink-0 animate-pulse-soft`}></div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-primary-800 truncate">{alert.source || 'Unknown'}</span>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${sev.bg} ${sev.text} shrink-0`}>
                  {alert.severity || 'medium'}
                </span>
              </div>
              <p className="mt-0.5 text-xs text-primary-500 truncate">{alert.category || 'Threat intelligence alert'}</p>
            </div>
          </div>
        )
      })}
    </div>
  )
}