import { useState, useEffect, useMemo } from 'react'
import { formatDate, formatTime } from '../utils/date'

const SEVERITY_CONFIG = {
  critical: { bg: 'bg-rose-500/10', text: 'text-rose-600', border: 'border-rose-500/20', dot: 'bg-rose-500', label: 'CRITICAL' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-600', border: 'border-orange-500/20', dot: 'bg-orange-500', label: 'HIGH' },
  medium: { bg: 'bg-amber-500/10', text: 'text-amber-600', border: 'border-amber-500/20', dot: 'bg-amber-500', label: 'MEDIUM' },
  low: { bg: 'bg-sky-500/10', text: 'text-sky-600', border: 'border-sky-500/20', dot: 'bg-sky-500', label: 'LOW' },
}

const STATUS_CONFIG = {
  new: { label: 'New', color: 'bg-slate-100 text-slate-600', icon: 'fiber_new' },
  assigned: { label: 'Assigned', color: 'bg-blue-100 text-blue-600', icon: 'person' },
  acknowledged: { label: 'Acknowledged', color: 'bg-amber-100 text-amber-600', icon: 'check_circle' },
  in_progress: { label: 'In Progress', color: 'bg-purple-100 text-purple-600', icon: 'pending' },
  resolved: { label: 'Resolved', color: 'bg-emerald-100 text-emerald-600', icon: 'done_all' },
  closed: { label: 'Closed', color: 'bg-slate-200 text-slate-500', icon: 'archive' },
}

const SLA_TIMERS = {
  critical: { ack: 15, resolve: 60 },
  high: { ack: 30, resolve: 120 },
  medium: { ack: 60, resolve: 240 },
  low: { ack: 240, resolve: 1440 },
}

export default function AlertTriagePanel({ axiosClient }) {
  const [alerts, setAlerts] = useState([])
  const [analysts, setAnalysts] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [filters, setFilters] = useState({ status: '', severity: '', assigned: '', unowned: false })
  const [showDetail, setShowDetail] = useState(false)
  const [notes, setNotes] = useState([])
  const [auditTrail, setAuditTrail] = useState([])
  const [newNote, setNewNote] = useState('')
  const [showAssignModal, setShowAssignModal] = useState(false)
  const [showResolveModal, setShowResolveModal] = useState(false)
  const [resolutionType, setResolutionType] = useState('')
  const [fpReason, setFpReason] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    try {
      setLoading(true)
      const [alertsRes, analystsRes] = await Promise.all([
        axiosClient.get('/alerts', { params: { limit: 100, include_payload: true } }),
        axiosClient.get('/users/analysts').catch(() => ({ data: [] }))
      ])
      setAlerts(alertsRes.data || [])
      setAnalysts(analystsRes.data || [])
    } catch (err) {
      console.error('Failed to load alerts:', err)
    } finally {
      setLoading(false)
    }
  }

  async function loadAlertDetails(alertId) {
    try {
      const [notesRes, auditRes] = await Promise.all([
        axiosClient.get(`/alerts/${alertId}/notes`),
        axiosClient.get(`/alerts/${alertId}/audit`)
      ])
      setNotes(notesRes.data || [])
      setAuditTrail(auditRes.data || [])
    } catch (err) {
      console.error('Failed to load alert details:', err)
    }
  }

  async function acknowledgeAlert(alertId) {
    try {
      await axiosClient.post(`/alerts/${alertId}/acknowledge`)
      showToast('Alert acknowledged', 'success')
      loadData()
      if (selectedAlert?.alert_id === alertId) {
        loadAlertDetails(alertId)
      }
    } catch (err) {
      showToast('Failed to acknowledge alert', 'error')
    }
  }

  async function assignAlert(alertId, userId) {
    try {
      await axiosClient.post(`/alerts/${alertId}/assign`, { user_id: userId })
      showToast('Alert assigned', 'success')
      loadData()
      setShowAssignModal(false)
    } catch (err) {
      showToast('Failed to assign alert', 'error')
    }
  }

  async function resolveAlert(alertId) {
    try {
      await axiosClient.post(`/alerts/${alertId}/resolve`, {
        status: 'resolved',
        resolution_type: resolutionType,
        reason: fpReason
      })
      showToast('Alert resolved', 'success')
      loadData()
      setShowResolveModal(false)
      setResolutionType('')
      setFpReason('')
    } catch (err) {
      showToast('Failed to resolve alert', 'error')
    }
  }

  async function addNote(alertId) {
    if (!newNote.trim()) return
    try {
      await axiosClient.post(`/alerts/${alertId}/notes`, { note: newNote })
      setNewNote('')
      loadAlertDetails(alertId)
      showToast('Note added', 'success')
    } catch (err) {
      showToast('Failed to add note', 'error')
    }
  }

  function showToast(message, type) {
    // Simple toast - in real app would use context
    console.log(`[${type}] ${message}`)
  }

  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      if (filters.status && alert.status !== filters.status) return false
      if (filters.severity && alert.severity !== filters.severity) return false
      if (filters.assigned && String(alert.assigned_to) !== filters.assigned) return false
      if (filters.unowned && alert.status !== 'new' && alert.assigned_to) return false
      return true
    })
  }, [alerts, filters])

  const stats = useMemo(() => ({
    total: alerts.length,
    new: alerts.filter(a => a.status === 'new').length,
    assigned: alerts.filter(a => a.status === 'assigned').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    inProgress: alerts.filter(a => a.status === 'in_progress').length,
    resolved: alerts.filter(a => a.status === 'resolved').length,
  }), [alerts])

  const handleAlertClick = (alert) => {
    setSelectedAlert(alert)
    setShowDetail(true)
    loadAlertDetails(alert.alert_id)
  }

  const SLA_COUNTDOWN_SLA = ({ alert }) => {
    const sla = SLA_TIMERS[alert.severity] || SLA_TIMERS.medium
    const startTime = formatDate(alert.received_at).getTime()
    const now = Date.now()
    const ackDeadline = startTime + (sla.ack * 60 * 1000)
    const resolveDeadline = startTime + (sla.resolve * 60 * 1000)
    
    const isAcked = alert.status === 'acknowledged' || alert.status === 'in_progress' || alert.status === 'resolved'
    const isResolved = alert.status === 'resolved' || alert.status === 'closed'
    
    const deadline = isAcked ? resolveDeadline : ackDeadline
    const remaining = Math.max(0, deadline - now)
    const minutes = Math.floor(remaining / 60000)
    const isBreached = remaining === 0 && !isResolved
    
    return (
      <span className={`text-[10px] font-mono font-bold ${isBreached ? 'text-red-600' : 'text-slate-400'}`}>
        {isResolved ? 'RESOLVED' : `${minutes}m remaining`}
      </span>
    )
  }

  return (
    <div className="space-y-6">
      {/* Stats Bar */}
      <div className="grid grid-cols-6 gap-3">
        {[
          { key: 'total', label: 'Total', color: 'bg-slate-100' },
          { key: 'new', label: 'New', color: 'bg-amber-100' },
          { key: 'assigned', label: 'Assigned', color: 'bg-blue-100' },
          { key: 'acknowledged', label: 'Ack\'d', color: 'bg-purple-100' },
          { key: 'inProgress', label: 'In Progress', color: 'bg-indigo-100' },
          { key: 'resolved', label: 'Resolved', color: 'bg-emerald-100' },
        ].map(stat => (
          <button
            key={stat.key}
            onClick={() => setFilters(f => ({ ...f, status: filters.status === stat.key ? '' : stat.key === 'new' ? 'new' : stat.key === 'assigned' ? 'assigned' : stat.key === 'acknowledged' ? 'acknowledged' : stat.key === 'inProgress' ? 'in_progress' : stat.key === 'resolved' ? 'resolved' : '' }))}
            className={`p-3 rounded-xl border transition-all ${stat.color} ${filters.status ? 'ring-2 ring-offset-2 ring-slate-400' : ''}`}
          >
            <div className="text-xl font-black text-slate-800">{stats[stat.key]}</div>
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">{stat.label}</div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 p-4 bg-white rounded-2xl border border-slate-200 shadow-sm">
        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Filters:</span>
        
        <select 
          value={filters.status} 
          onChange={e => setFilters(f => ({ ...f, status: e.target.value }))}
          className="px-3 py-2 text-xs font-semibold rounded-lg border border-slate-200 bg-slate-50"
        >
          <option value="">All Statuses</option>
          {Object.entries(STATUS_CONFIG).map(([key, val]) => (
            <option key={key} value={key}>{val.label}</option>
          ))}
        </select>

        <select 
          value={filters.severity} 
          onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}
          className="px-3 py-2 text-xs font-semibold rounded-lg border border-slate-200 bg-slate-50"
        >
          <option value="">All Severities</option>
          {Object.entries(SEVERITY_CONFIG).map(([key, val]) => (
            <option key={key} value={key}>{val.label}</option>
          ))}
        </select>

        <select 
          value={filters.assigned} 
          onChange={e => setFilters(f => ({ ...f, assigned: e.target.value }))}
          className="px-3 py-2 text-xs font-semibold rounded-lg border border-slate-200 bg-slate-50"
        >
          <option value="">All Analysts</option>
          {analysts.map(analyst => (
            <option key={analyst.id} value={analyst.id}>{analyst.full_name}</option>
          ))}
        </select>

        <label className="flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-lg border border-slate-200 bg-slate-50 cursor-pointer">
          <input 
            type="checkbox" 
            checked={filters.unowned}
            onChange={e => setFilters(f => ({ ...f, unowned: e.target.checked }))}
            className="rounded" 
          />
          Unowned Only
        </label>

        <button onClick={loadData} className="ml-auto p-2 text-slate-400 hover:text-sky-500 transition-colors">
          <span className="material-symbols-outlined">refresh</span>
        </button>
      </div>

      {/* Alert List */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Severity</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Alert</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Source</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Assigned To</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">SLA</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Age</th>
                <th className="px-4 py-3 text-left text-[10px] font-black text-slate-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-slate-400">Loading...</td></tr>
              ) : filteredAlerts.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-slate-400">No alerts match filters</td></tr>
              ) : (
                filteredAlerts.map(alert => {
                  const sev = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.medium
                  const status = STATUS_CONFIG[alert.status] || STATUS_CONFIG.new
                  return (
                    <tr key={alert.alert_id} className="hover:bg-slate-50 cursor-pointer transition-colors" onClick={() => handleAlertClick(alert)}>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest border ${sev.border} ${sev.text} ${sev.bg}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`}></span>
                          {sev.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-xs font-bold text-slate-700 truncate max-w-[200px]">{alert.category || 'Alert'}</div>
                        <div className="text-[10px] text-slate-400 font-mono">{alert.alert_id}</div>
                      </td>
                      <td className="px-4 py-3 text-xs font-semibold text-slate-600">{alert.source}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-[9px] font-bold ${status.color}`}>
                          <span className="material-symbols-outlined text-[12px]">{status.icon}</span>
                          {status.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {alert.assignee_name ? (
                          <span className="text-xs font-semibold text-slate-700">{alert.assignee_name}</span>
                        ) : (
                          <span className="text-xs text-slate-400 italic">Unassigned</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <SLA_COUNTDOWN_SLA alert={alert} />
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-slate-400">
                        {formatTime(alert.received_at)}
                      </td>
                      <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
                          {alert.status === 'new' && (
                            <button onClick={() => acknowledgeAlert(alert.alert_id)} className="p-1.5 text-slate-400 hover:text-amber-500 hover:bg-amber-50 rounded-lg transition-colors" title="Acknowledge">
                              <span className="material-symbols-outlined text-[16px]">check_circle</span>
                            </button>
                          )}
                          <button onClick={() => { setSelectedAlert(alert); setShowAssignModal(true) }} className="p-1.5 text-slate-400 hover:text-blue-500 hover:bg-blue-50 rounded-lg transition-colors" title="Assign">
                            <span className="material-symbols-outlined text-[16px]">person_add</span>
                          </button>
                          {(alert.status === 'acknowledged' || alert.status === 'in_progress') && (
                            <button onClick={() => { setSelectedAlert(alert); setShowResolveModal(true) }} className="p-1.5 text-slate-400 hover:text-emerald-500 hover:bg-emerald-50 rounded-lg transition-colors" title="Resolve">
                              <span className="material-symbols-outlined text-[16px]">done_all</span>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {showDetail && selectedAlert && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowDetail(false)}>
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col" onClick={e => e.stopPropagation()}>
            {/* Header */}
            <div className="p-6 border-b border-slate-200 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest border ${SEVERITY_CONFIG[selectedAlert.severity]?.border || 'border-slate-200'} ${SEVERITY_CONFIG[selectedAlert.severity]?.text || 'text-slate-600'} ${SEVERITY_CONFIG[selectedAlert.severity]?.bg || 'bg-slate-100'}`}>
                    {selectedAlert.severity?.toUpperCase() || 'MEDIUM'}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-[10px] font-bold ${STATUS_CONFIG[selectedAlert.status]?.color || STATUS_CONFIG.new.color}`}>
                    {STATUS_CONFIG[selectedAlert.status]?.label || 'New'}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-slate-800 mt-2">{selectedAlert.category || 'Alert'}</h2>
                <p className="text-xs text-slate-400 font-mono mt-1">{selectedAlert.alert_id}</p>
              </div>
              <button onClick={() => setShowDetail(false)} className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors">
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-6">
              <div className="grid grid-cols-3 gap-6">
                {/* Main Info */}
                <div className="col-span-2 space-y-6">
                  {/* Payload */}
                  <div className="bg-slate-900 rounded-xl p-4 overflow-x-auto">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Raw Event</span>
                      <button onClick={() => navigator.clipboard.writeText(JSON.stringify(selectedAlert.payload, null, 2))} className="text-xs text-sky-400 hover:text-sky-300">Copy</button>
                    </div>
                    <pre className="text-[10px] text-sky-400 font-mono">{JSON.stringify(selectedAlert.payload, null, 2)}</pre>
                  </div>

                  {/* Notes */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-700 mb-3">Analyst Notes</h3>
                    <div className="space-y-2 mb-3">
                      {notes.map((note, idx) => (
                        <div key={idx} className="p-3 bg-slate-50 rounded-lg">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-bold text-slate-600">{note.author_name}</span>
                            <span className="text-[10px] text-slate-400">{new Date(note.created_at).toLocaleString()}</span>
                          </div>
                          <p className="text-xs text-slate-600">{note.note}</p>
                        </div>
                      ))}
                      {notes.length === 0 && <p className="text-xs text-slate-400 italic">No notes yet</p>}
                    </div>
                    <div className="flex gap-2">
                      <input 
                        type="text" 
                        value={newNote}
                        onChange={e => setNewNote(e.target.value)}
                        placeholder="Add a note..."
                        className="flex-1 px-3 py-2 text-xs border border-slate-200 rounded-lg"
                        onKeyDown={e => e.key === 'Enter' && addNote(selectedAlert.alert_id)}
                      />
                      <button onClick={() => addNote(selectedAlert.alert_id)} className="px-3 py-2 bg-slate-900 text-white text-xs font-bold rounded-lg hover:bg-slate-800">Add</button>
                    </div>
                  </div>

                  {/* Audit Trail */}
                  <div>
                    <h3 className="text-sm font-bold text-slate-700 mb-3">Audit Trail</h3>
                    <div className="space-y-2">
                      {auditTrail.map((entry, idx) => (
                        <div key={idx} className="flex items-center gap-3 p-2 border-l-2 border-slate-200">
                          <span className="text-[10px] text-slate-400">{new Date(entry.created_at).toLocaleString()}</span>
                          <span className="text-xs font-semibold text-slate-600">{entry.actor_name || 'System'}</span>
                          <span className="text-xs text-slate-500">{entry.action}</span>
                        </div>
                      ))}
                      {auditTrail.length === 0 && <p className="text-xs text-slate-400 italic">No audit entries</p>}
                    </div>
                  </div>
                </div>

                {/* Sidebar */}
                <div className="space-y-4">
                  {/* Assignment */}
                  <div className="p-4 bg-slate-50 rounded-xl">
                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Assignment</h4>
                    <p className="text-sm font-semibold text-slate-700">{selectedAlert.assignee_name || 'Unassigned'}</p>
                    <button onClick={() => setShowAssignModal(true)} className="mt-2 w-full py-2 text-xs font-bold text-sky-600 hover:bg-sky-50 rounded-lg transition-colors">
                      Change Assignment
                    </button>
                  </div>

                  {/* Asset Context (if available) */}
                  {(selectedAlert.asset_hostname || selectedAlert.asset_owner) && (
                    <div className="p-4 bg-slate-50 rounded-xl">
                      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Asset Context</h4>
                      {selectedAlert.asset_hostname && <p className="text-xs text-slate-600"><span className="font-bold">Host:</span> {selectedAlert.asset_hostname}</p>}
                      {selectedAlert.asset_owner && <p className="text-xs text-slate-600"><span className="font-bold">Owner:</span> {selectedAlert.asset_owner}</p>}
                      {selectedAlert.asset_criticality && <p className="text-xs text-slate-600"><span className="font-bold">Criticality:</span> {selectedAlert.asset_criticality}</p>}
                    </div>
                  )}

                  {/* MITRE Tags */}
                  {(selectedAlert.mitre_tactics?.length > 0 || selectedAlert.mitre_techniques?.length > 0) && (
                    <div className="p-4 bg-slate-50 rounded-xl">
                      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">MITRE ATT&CK</h4>
                      <div className="flex flex-wrap gap-1">
                        {[...(selectedAlert.mitre_tactics || []), ...(selectedAlert.mitre_techniques || [])].map((tag, idx) => (
                          <span key={idx} className="px-2 py-0.5 bg-red-100 text-red-600 text-[9px] font-bold rounded">{tag}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Containment */}
                  {selectedAlert.containment_status && (
                    <div className="p-4 bg-slate-50 rounded-xl">
                      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Containment</h4>
                      <p className="text-xs text-slate-600">{selectedAlert.containment_status}</p>
                      {selectedAlert.containment_action && <p className="text-[10px] text-slate-400 mt-1">{selectedAlert.containment_action}</p>}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Footer Actions */}
            <div className="p-4 border-t border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {selectedAlert.status === 'new' && (
                  <button onClick={() => acknowledgeAlert(selectedAlert.alert_id)} className="px-4 py-2 bg-amber-500 text-white text-xs font-bold rounded-lg hover:bg-amber-600">
                    Acknowledge
                  </button>
                )}
                {(selectedAlert.status === 'acknowledged' || selectedAlert.status === 'in_progress') && (
                  <button onClick={() => setShowResolveModal(true)} className="px-4 py-2 bg-emerald-500 text-white text-xs font-bold rounded-lg hover:bg-emerald-600">
                    Resolve
                  </button>
                )}
              </div>
              <button onClick={() => setShowDetail(false)} className="px-4 py-2 text-slate-500 text-xs font-bold hover:bg-slate-100 rounded-lg">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Assign Modal */}
      {showAssignModal && selectedAlert && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowAssignModal(false)}>
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-slate-800 mb-4">Assign Alert</h3>
            <div className="space-y-2 mb-4">
              {analysts.map(analyst => (
                <button
                  key={analyst.id}
                  onClick={() => assignAlert(selectedAlert.alert_id, analyst.id)}
                  className="w-full p-3 text-left border border-slate-200 rounded-lg hover:border-sky-500 hover:bg-sky-50 transition-colors"
                >
                  <div className="text-sm font-semibold text-slate-700">{analyst.full_name}</div>
                  <div className="text-xs text-slate-400">{analyst.email}</div>
                </button>
              ))}
            </div>
            <button onClick={() => setShowAssignModal(false)} className="w-full py-2 text-slate-500 text-xs font-bold hover:bg-slate-100 rounded-lg">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Resolve Modal */}
      {showResolveModal && selectedAlert && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowResolveModal(false)}>
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-slate-800 mb-4">Resolve Alert</h3>
            
            <div className="space-y-2 mb-4">
              {[
                { value: 'true_positive', label: 'True Positive', desc: 'Confirmed security threat' },
                { value: 'false_positive', label: 'False Positive', desc: 'Benign event, no action needed' },
                { value: 'benign_positive', label: 'Benign Positive', desc: 'Expected behavior' },
                { value: 'indeterminate', label: 'Indeterminate', desc: 'Unable to determine' },
              ].map(opt => (
                <label key={opt.value} className="flex items-center gap-3 p-3 border border-slate-200 rounded-lg cursor-pointer hover:border-sky-500">
                  <input type="radio" name="resolution" value={opt.value} checked={resolutionType === opt.value} onChange={e => setResolutionType(e.target.value)} className="text-sky-500" />
                  <div>
                    <div className="text-sm font-semibold text-slate-700">{opt.label}</div>
                    <div className="text-xs text-slate-400">{opt.desc}</div>
                  </div>
                </label>
              ))}
            </div>

            {resolutionType === 'false_positive' && (
              <div className="mb-4">
                <label className="block text-xs font-bold text-slate-500 mb-1">Reason (optional)</label>
                <select value={fpReason} onChange={e => setFpReason(e.target.value)} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm">
                  <option value="">Select reason...</option>
                  <option value="noisy_rule">Noisy rule</option>
                  <option value="test_traffic">Test traffic</option>
                  <option value="whitelisted">Whitelisted asset</option>
                  <option value="known_issue">Known issue</option>
                  <option value="other">Other</option>
                </select>
              </div>
            )}

            <div className="flex gap-2">
              <button onClick={() => resolveAlert(selectedAlert.alert_id)} disabled={!resolutionType} className="flex-1 py-2 bg-emerald-500 text-white text-xs font-bold rounded-lg hover:bg-emerald-600 disabled:opacity-50">
                Resolve
              </button>
              <button onClick={() => setShowResolveModal(false)} className="px-4 py-2 text-slate-500 text-xs font-bold hover:bg-slate-100 rounded-lg">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
