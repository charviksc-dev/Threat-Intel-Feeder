import { useState, useEffect, useMemo } from 'react'
import { formatDate, formatTime, formatRelativeTime } from '../utils/date'

const SLA_CONFIG = {
  critical: { ack: 15, resolve: 60 },
  high: { ack: 30, resolve: 120 },
  medium: { ack: 60, resolve: 240 },
  low: { ack: 240, resolve: 1440 },
}

const PAGE_SIZE = 25

function SLATimer({ alert, now }) {
  const sla = SLA_CONFIG[alert.severity] || SLA_CONFIG.medium
  const startTime = formatDate(alert.received_at).getTime()
  
  const isAcked = ['acknowledged', 'in_progress', 'resolved', 'closed'].includes(alert.status)
  const ackDeadline = startTime + (sla.ack * 60 * 1000)
  const resolveDeadline = startTime + (sla.resolve * 60 * 1000)
  const deadline = isAcked ? resolveDeadline : ackDeadline
  
  const remaining = Math.max(0, deadline - now)
  const minutes = Math.floor(remaining / 60000)
  const isBreached = remaining === 0 && !['resolved', 'closed'].includes(alert.status)
  const isWarning = remaining > 0 && remaining < (sla.ack * 60 * 1000 * 0.25)
  
  if (['resolved', 'closed'].includes(alert.status)) {
    return <span className="text-[10px] font-bold text-emerald-500">RESOLVED</span>
  }
  
  if (isBreached) {
    return <span className="text-[10px] font-black text-red-600 animate-pulse">BREACHED</span>
  }
  
  if (isWarning && !isAcked) {
    return <span className="text-[10px] font-bold text-amber-600">{minutes}m</span>
  }
  
  return <span className="text-[10px] font-mono text-slate-400">{minutes}m</span>
}

export default function AlertTriageTable({ axiosClient, onAlertClick, refreshKey = 0 }) {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState({ status: '', severity: '' })
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    fetchAlerts()
  }, [filter, refreshKey])

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 60000)
    return () => clearInterval(interval)
  }, [])

  async function fetchAlerts() {
    setLoading(true)
    try {
      const params = {}
      if (filter.status) params.status = filter.status
      if (filter.severity) params.severity = filter.severity
      
      const res = await axiosClient.get('/alerts', { params: { ...params, limit: PAGE_SIZE } })
      setAlerts(res.data)
    } catch (err) {
      console.error('Failed to fetch alerts', err)
    } finally {
      setLoading(false)
    }
  }

  const stats = useMemo(() => ({
    total: alerts.length,
    unacknowledged: alerts.filter(a => !['acknowledged', 'in_progress', 'resolved', 'closed'].includes(a.status)).length,
    breaching: alerts.filter(a => {
      const sla = SLA_CONFIG[a.severity] || SLA_CONFIG.medium
      const startTime = new Date(a.received_at).getTime()
      const isAcked = ['acknowledged', 'in_progress', 'resolved', 'closed'].includes(a.status)
      const deadline = isAcked 
        ? startTime + (sla.resolve * 60 * 1000)
        : startTime + (sla.ack * 60 * 1000)
      return deadline - now < 0 && !['resolved', 'closed'].includes(a.status)
    }).length,
  }), [alerts, now])

  const severityConfig = {
    critical: { bg: 'bg-rose-500/10', text: 'text-rose-600', border: 'border-rose-500/20', dot: 'bg-rose-500' },
    high: { bg: 'bg-orange-500/10', text: 'text-orange-600', border: 'border-orange-500/20', dot: 'bg-orange-500' },
    medium: { bg: 'bg-amber-500/10', text: 'text-amber-600', border: 'border-amber-500/20', dot: 'bg-amber-500' },
    low: { bg: 'bg-sky-500/10', text: 'text-sky-600', border: 'border-sky-500/20', dot: 'bg-sky-500' },
  }

  const statusTags = {
    new: 'bg-blue-100 text-blue-700',
    assigned: 'bg-indigo-100 text-indigo-700',
    acknowledged: 'bg-amber-100 text-amber-700',
    in_progress: 'bg-purple-100 text-purple-700',
    resolved: 'bg-emerald-100 text-emerald-700',
    closed: 'bg-slate-100 text-slate-700'
  }

  return (
    <div className="space-y-6">
      {/* Stats & Filters Bar */}
      <div className="flex items-center justify-between gap-4 p-4 rounded-3xl bg-white border border-slate-100 shadow-sm">
        <div className="flex items-center gap-6">
          {/* Quick Stats */}
          <div className="flex items-center gap-4 mr-4 pr-4 border-r border-slate-100">
            <div className="text-center">
              <div className="text-lg font-black text-slate-800">{stats.total}</div>
              <div className="text-[9px] font-bold text-slate-400 uppercase">Total</div>
            </div>
            {stats.unacknowledged > 0 && (
              <div className="text-center">
                <div className="text-lg font-black text-amber-600">{stats.unacknowledged}</div>
                <div className="text-[9px] font-bold text-amber-500 uppercase">Pending</div>
              </div>
            )}
            {stats.breaching > 0 && (
              <div className="text-center">
                <div className="text-lg font-black text-red-600">{stats.breaching}</div>
                <div className="text-[9px] font-bold text-red-500 uppercase">Breaching</div>
              </div>
            )}
          </div>
          
          <div className="flex items-center gap-3">
             <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Status</span>
             <div className="flex bg-slate-100 p-1 rounded-xl">
               {['', 'new', 'assigned', 'acknowledged', 'in_progress', 'resolved'].map(s => (
                 <button 
                  key={s}
                  onClick={() => setFilter({...filter, status: s})}
                  className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-tight transition-all ${filter.status === s ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-400 hover:text-slate-600'}`}
                 >
                   {s || 'All'}
                 </button>
               ))}
             </div>
           </div>
           <div className="flex items-center gap-3">
             <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Severity</span>
             <select 
              value={filter.severity}
              onChange={e => setFilter({...filter, severity: e.target.value})}
              className="px-4 py-1.5 bg-slate-100 border-none rounded-xl text-[10px] font-black uppercase tracking-widest text-slate-600 cursor-pointer focus:ring-0"
             >
               <option value="">All Tiers</option>
               <option value="critical">Critical</option>
               <option value="high">High</option>
               <option value="medium">Medium</option>
               <option value="low">Low</option>
             </select>
           </div>
        </div>
        <button onClick={fetchAlerts} className="w-9 h-9 rounded-xl bg-slate-50 text-slate-400 hover:bg-sky-50 hover:text-sky-500 transition-all flex items-center justify-center border border-slate-100">
          <span className={`material-symbols-outlined text-[18px] ${loading ? 'animate-spin' : ''}`}>refresh</span>
        </button>
      </div>

      {/* Main Table */}
      <div className="bg-white rounded-[32px] border border-slate-100 shadow-xl shadow-slate-200/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="bg-slate-50/50 border-b border-slate-100">
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">Triage Data</th>
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">Sensor</th>
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">Severity</th>
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">Status</th>
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">Assignee</th>
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">SLA</th>
                <th className="px-8 py-5 text-left text-[10px] font-black uppercase tracking-widest text-slate-400">Arrival (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {alerts.map((alert, idx) => {
                const sev = severityConfig[alert.severity] || severityConfig.medium
                return (
                  <tr 
                    key={alert.alert_id} 
                    onClick={() => onAlertClick(alert)}
                    className="group hover:bg-slate-50/80 cursor-pointer transition-colors animate-slide-up"
                    style={{ animationDelay: `${idx * 0.02}s` }}
                  >
                    <td className="px-8 py-5">
                      <div>
                        <div className="text-sm font-black text-slate-900 line-clamp-1">{alert.category || 'Undetermined Threat'}</div>
                        <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-2">
                           <span className="font-mono">{(alert.alert_id || '').slice(0, 8)}...</span>
                           {alert.asset_hostname && <span className="px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-500 border border-slate-200">@{alert.asset_hostname}</span>}
                        </div>
                      </div>
                    </td>
                    <td className="px-8 py-5">
                      <span className="px-3 py-1 rounded-lg bg-slate-100 text-slate-600 text-[10px] font-black uppercase border border-slate-200">
                        {alert.source || 'Unknown'}
                      </span>
                    </td>
                    <td className="px-8 py-5">
                       <div className="flex items-center gap-2">
                         <div className={`w-2 h-2 rounded-full ${sev.dot} shadow-[0_0_8px] shadow-current`}></div>
                         <span className={`text-[10px] font-black uppercase tracking-widest ${sev.text}`}>{alert.severity}</span>
                       </div>
                    </td>
                    <td className="px-8 py-5">
                       <span className={`px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest border border-current/10 ${statusTags[alert.status] || statusTags.new}`}>
                          {alert.status || 'new'}
                        </span>
                    </td>
                    <td className="px-8 py-5">
                       <div className="flex items-center gap-2">
                        {alert.assignee_name ? (
                          <div className="w-7 h-7 rounded-full bg-sky-500 flex items-center justify-center text-[10px] font-black text-white border-2 border-white shadow-sm" title={alert.assignee_name}>
                            {alert.assignee_name[0]}
                          </div>
                        ) : (
                          <span className="text-[10px] text-slate-300 pointer-events-none italic font-bold">Unassigned</span>
                        )}
                       </div>
                    </td>
                    <td className="px-8 py-5">
                      <SLATimer alert={alert} now={now} />
                    </td>
                    <td className="px-8 py-5">
                       <div className="text-[10px] font-bold text-slate-500">
                          <div>{formatDate(alert.received_at).toLocaleDateString()}</div>
                          <div className="opacity-60">{formatTime(alert.received_at)}</div>
                       </div>
                    </td>
                  </tr>
                )
              })}
               {alerts.length === 0 && !loading && (
                  <tr>
                     <td colSpan="7" className="py-20 text-center">
                        <div className="flex flex-col items-center justify-center text-slate-300">
                           <span className="material-symbols-outlined text-4xl mb-4">task</span>
                           <p className="text-xs font-black uppercase tracking-widest">Inbox Zero</p>
                           <p className="text-[10px] mt-1 font-bold opacity-60">All threats in this view have been dispositioned</p>
                        </div>
                     </td>
                  </tr>
               )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
