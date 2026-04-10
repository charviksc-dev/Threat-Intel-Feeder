import { useEffect, useMemo, useState } from 'react'

export default function AlertDetailModal({ alert, axiosClient, onClose, onRefresh }) {
  const [activeTab, setActiveTab] = useState('investigation')
  const [notes, setNotes] = useState([])
  const [auditLog, setAuditLog] = useState([])
  const [analysts, setAnalysts] = useState([])
  const [newNote, setNewNote] = useState('')
  const [loading, setLoading] = useState(false)
  const [resolution, setResolution] = useState({ type: 'true_positive', reason: '' })
  const [showAssignDropdown, setShowAssignDropdown] = useState(false)
  const [pushingToTheHive, setPushingToTheHive] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [alertDetail, setAlertDetail] = useState(null)
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const alertId = alert?.alert_id
  const currentAlert = alertDetail || alert

  useEffect(() => {
    if (!alertId) return
    setActiveTab('investigation')
    setShowAssignDropdown(false)
    setAiAnalysis(null)
    fetchData(alertId)
    fetchAnalysts()
  }, [alertId])

  useEffect(() => {
    if (activeTab === 'ai_explain' && alertId && !aiAnalysis && !aiLoading) {
      loadAiAnalysis()
    }
  }, [activeTab, alertId, aiAnalysis, aiLoading])

  async function fetchData(targetAlertId = alertId) {
    if (!targetAlertId) return
    try {
      const [detailRes, notesRes, auditRes] = await Promise.all([
        axiosClient.get(`/alerts/${targetAlertId}`, { params: { include_payload: true } }),
        axiosClient.get(`/alerts/${targetAlertId}/notes`),
        axiosClient.get(`/alerts/${targetAlertId}/audit`),
      ])
      setAlertDetail(detailRes.data || null)
      setNotes(notesRes.data || [])
      setAuditLog(auditRes.data || [])
    } catch (err) {
      console.error('Failed to fetch alert details', err)
    }
  }

  async function fetchAnalysts() {
    try {
      const res = await axiosClient.get('/users/analysts')
      setAnalysts(res.data || [])
    } catch (err) {
      console.error('Failed to fetch analysts', err)
    }
  }

  async function loadAiAnalysis() {
    if (!alertId) return
    setAiLoading(true)
    try {
      const res = await axiosClient.get(`/alerts/${alertId}/analysis`)
      setAiAnalysis(res.data || null)
    } catch (err) {
      console.error('Failed to load AI analysis', err)
      window.alert('Unable to generate AI explanation for this log right now.')
    } finally {
      setAiLoading(false)
    }
  }

  async function refreshAll() {
    await Promise.all([
      Promise.resolve(onRefresh?.()),
      fetchData(alertId),
    ])
  }

  async function handleAction(action) {
    if (!alertId) return
    setLoading(true)
    try {
      if (action === 'acknowledge') {
        await axiosClient.post(`/alerts/${alertId}/acknowledge`)
      } else if (action === 'resolve') {
        await axiosClient.post(`/alerts/${alertId}/resolve`, {
          status: 'resolved',
          resolution_type: resolution.type,
          reason: resolution.reason,
        })
      }
      await refreshAll()
    } catch (err) {
      console.error(`Action ${action} failed`, err)
    } finally {
      setLoading(false)
    }
  }

  async function handleAssign(userId) {
    if (!alertId) return
    setLoading(true)
    try {
      await axiosClient.post(`/alerts/${alertId}/assign`, { user_id: userId })
      setShowAssignDropdown(false)
      await refreshAll()
    } catch (err) {
      console.error('Assignment failed', err)
    } finally {
      setLoading(false)
    }
  }

  async function handleDelete() {
    if (!alertId) return
    const confirmed = window.confirm('Delete this alert permanently? This cannot be undone.')
    if (!confirmed) return

    setDeleting(true)
    try {
      await axiosClient.delete(`/alerts/${alertId}`)
      await Promise.resolve(onRefresh?.())
      onClose?.()
    } catch (err) {
      console.error('Delete failed', err)
      window.alert('Failed to delete alert. You may need admin or SOC manager permissions.')
    } finally {
      setDeleting(false)
    }
  }

  async function pushToTheHive() {
    if (!alertId) return
    setPushingToTheHive(true)
    try {
      const res = await axiosClient.post(`/alerts/${alertId}/thehive`)
      if (res.data.status === 'success') {
        window.alert(`Alert pushed to TheHive! Case ID: ${res.data.thehive_id}`)
        await fetchData(alertId)
      }
    } catch (err) {
      console.error('TheHive push failed', err)
      window.alert('Failed to push to TheHive. Make sure TheHive is configured.')
    } finally {
      setPushingToTheHive(false)
    }
  }

  async function addNote() {
    if (!alertId || !newNote.trim()) return
    try {
      await axiosClient.post(`/alerts/${alertId}/notes`, { note: newNote })
      setNewNote('')
      await fetchData(alertId)
    } catch (err) {
      console.error('Failed to add note', err)
    }
  }

  const severityColors = {
    critical: 'bg-rose-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-sky-500',
  }

  const statusColors = {
    new: 'bg-blue-500',
    assigned: 'bg-indigo-500',
    acknowledged: 'bg-amber-500',
    in_progress: 'bg-purple-500',
    resolved: 'bg-emerald-500',
    closed: 'bg-slate-500',
  }

  if (!alert) return null

  const payloadJson = JSON.stringify(currentAlert?.payload || {}, null, 2)
  const iocForLookup = useMemo(() => {
    const payload = currentAlert?.payload
    if (!payload || typeof payload !== 'object') return ''
    const byPriority = [
      payload.src_ip,
      payload.source_ip,
      payload.client_ip,
      payload.dst_ip,
      payload.dest_ip,
      payload.url,
      payload.uri,
      payload.domain,
      payload.hostname,
      payload.sha256,
      payload.sha1,
      payload.md5,
      payload.hash,
      payload.file_hash,
      payload?.agent?.ip,
      payload?.agent?.name,
    ]
    return String(byPriority.find(Boolean) || '').trim()
  }, [currentAlert])

  function openLookupTool(tool) {
    if (!iocForLookup) {
      window.alert('No IOC was found in this alert payload to lookup externally.')
      return
    }
    const encoded = encodeURIComponent(iocForLookup)
    const links = {
      virustotal: `https://www.virustotal.com/gui/search/${encoded}`,
      abuseipdb: `https://www.abuseipdb.com/check/${encoded}`,
      otx: `https://otx.alienvault.com/browse/global/pulses?q=${encoded}`,
    }
    const url = links[tool]
    if (url) window.open(url, '_blank', 'noopener,noreferrer')
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-fade-in">
      <div className="bg-white w-full max-w-5xl h-[85vh] rounded-3xl shadow-2xl overflow-hidden flex flex-col animate-scale-up">
        {/* Header */}
        <div className="px-8 py-6 border-b border-slate-100 bg-slate-50/50 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-2xl ${severityColors[currentAlert?.severity] || 'bg-slate-500'} flex items-center justify-center text-white shadow-lg`}>
              <span className="material-symbols-outlined text-2xl">warning</span>
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-black text-slate-900 tracking-tight">{currentAlert?.source || 'Unknown'} Alert</h2>
                <span className={`text-[10px] font-black uppercase tracking-widest px-2.5 py-1 rounded-lg text-white ${statusColors[currentAlert?.status] || 'bg-slate-500'}`}>
                  {currentAlert?.status || 'new'}
                </span>
              </div>
              <p className="text-xs text-slate-500 font-mono mt-1">ID: {currentAlert?.alert_id}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-xl hover:bg-slate-100 transition-colors">
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 flex overflow-hidden">
          {/* Left Panel: Tabs & Actions */}
          <div className="w-72 border-r border-slate-100 p-6 space-y-8 overflow-y-auto">
            <div>
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400 mb-4">Triage Actions</h3>
              <div className="space-y-2">
                {currentAlert?.status === 'new' && (
                  <button
                    onClick={() => handleAction('acknowledge')}
                    disabled={loading}
                    className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-amber-50 text-amber-600 border border-amber-100 hover:bg-amber-100 transition-all font-bold text-sm shadow-sm disabled:opacity-60"
                  >
                    <span className="material-symbols-outlined text-[18px]">verified_user</span>
                    Acknowledge
                  </button>
                )}
                <button
                  onClick={() => setActiveTab('resolve')}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-emerald-50 text-emerald-600 border border-emerald-100 hover:bg-emerald-100 transition-all font-bold text-sm shadow-sm"
                >
                  <span className="material-symbols-outlined text-[18px]">task_alt</span>
                  Resolve Alert
                </button>
                <button
                  onClick={pushToTheHive}
                  disabled={pushingToTheHive}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-red-50 text-red-600 border border-red-100 hover:bg-red-100 transition-all font-bold text-sm shadow-sm disabled:opacity-60"
                >
                  <span className="material-symbols-outlined text-[18px]">{pushingToTheHive ? 'hourglass_top' : 'launch'}</span>
                  {pushingToTheHive ? 'Pushing...' : 'Push to TheHive'}
                </button>
                <div className="relative">
                  <button
                    onClick={() => setShowAssignDropdown(!showAssignDropdown)}
                    className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-sky-50 text-sky-600 border border-sky-100 hover:bg-sky-100 transition-all font-bold text-sm shadow-sm"
                  >
                    <span className="material-symbols-outlined text-[18px]">person_add</span>
                    {currentAlert?.assignee_name ? `Assigned to ${currentAlert.assignee_name}` : 'Assign to...'}
                  </button>
                  {showAssignDropdown && (
                    <div className="absolute top-full left-0 right-0 mt-2 bg-white border border-slate-200 rounded-xl shadow-xl z-10 max-h-48 overflow-y-auto">
                      {analysts.map(analyst => (
                        <button
                          key={analyst.id}
                          onClick={() => handleAssign(analyst.id)}
                          className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 flex items-center gap-2"
                        >
                          <div className="w-6 h-6 rounded-full bg-sky-500 text-white flex items-center justify-center text-xs font-bold">
                            {analyst.full_name?.charAt(0) || analyst.email?.charAt(0)}
                          </div>
                          <div>
                            <div className="font-semibold text-slate-700">{analyst.full_name || analyst.email}</div>
                          </div>
                        </button>
                      ))}
                      {analysts.length === 0 && (
                        <div className="px-4 py-3 text-xs text-slate-400">No analysts available</div>
                      )}
                    </div>
                  )}
                </div>
                <button
                  onClick={handleDelete}
                  disabled={deleting}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100 transition-all font-bold text-sm shadow-sm disabled:opacity-60"
                >
                  <span className="material-symbols-outlined text-[18px]">delete</span>
                  {deleting ? 'Deleting...' : 'Delete Alert'}
                </button>
              </div>
            </div>

            <nav className="space-y-1">
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400 mb-4">Investigation</h3>
              {[
                { id: 'investigation', label: 'Summary', icon: 'info' },
                { id: 'payload', label: 'Raw Payload', icon: 'code' },
                { id: 'ai_explain', label: 'AI Explain', icon: 'psychology' },
                { id: 'notes', label: 'Analyst Notes', icon: 'edit_note' },
                { id: 'audit', label: 'Audit Trail', icon: 'history' },
                { id: 'enrichment', label: 'Enrichment', icon: 'hub' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all ${activeTab === tab.id ? 'bg-slate-900 text-white shadow-lg' : 'text-slate-500 hover:bg-slate-50'}`}
                >
                  <span className="material-symbols-outlined text-[18px]">{tab.icon}</span>
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>

          {/* Right Panel: Tab Content */}
          <div className="flex-1 overflow-y-auto p-8 bg-slate-50/10">
            {activeTab === 'investigation' && (
              <div className="space-y-6 animate-fade-in">
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm">
                    <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-2">Detection Source</h4>
                    <p className="text-sm font-bold text-slate-800">{currentAlert?.source || 'Unknown'}</p>
                    <p className="text-[10px] text-slate-500 mt-1">Rule ID: {currentAlert?.payload?.rule?.id || currentAlert?.sensor_rule_id || 'N/A'}</p>
                  </div>
                  <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm">
                    <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-2">Confidence Score</h4>
                    <div className="flex items-center gap-2">
                      <span className="text-xl font-black text-slate-900">{currentAlert?.severity === 'critical' ? '95%' : currentAlert?.severity === 'high' ? '80%' : '60%'}</span>
                      <div className="w-24 h-2 bg-slate-100 rounded-full overflow-hidden">
                        <div className={`h-full ${severityColors[currentAlert?.severity] || 'bg-slate-500'} rounded-full`} style={{ width: currentAlert?.severity === 'critical' ? '95%' : '80%' }}></div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                  <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-4">Affected Assets</h4>
                  <div className="flex items-center gap-4 p-4 rounded-xl bg-slate-50 border border-slate-100 hover:border-sky-200 transition-all group">
                    <div className="w-10 h-10 rounded-xl bg-white flex items-center justify-center text-slate-400 group-hover:text-sky-500 shadow-sm transition-colors">
                      <span className="material-symbols-outlined">computer</span>
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-800">{currentAlert?.payload?.agent?.name || currentAlert?.asset_hostname || 'Unknown Host'}</p>
                      <p className="text-[10px] text-slate-500">IP: {currentAlert?.payload?.agent?.ip || 'N/A'} • OS: {currentAlert?.payload?.agent?.os?.name || 'Unknown'}</p>
                    </div>
                  </div>
                </div>

                <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                  <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-4">MITRE ATT&CK Mapping</h4>
                  <div className="flex flex-wrap gap-2">
                    {currentAlert?.payload?.rule?.mitre?.id?.map(id => (
                      <span key={id} className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-sky-50 text-sky-600 text-[10px] font-black border border-sky-100 uppercase tracking-tight">
                        <span className="material-symbols-outlined text-[12px]">rebase_edit</span>
                        {id}
                      </span>
                    ))}
                    {(!currentAlert?.payload?.rule?.mitre?.id || currentAlert.payload.rule.mitre.id.length === 0) && (
                      <p className="text-xs text-slate-400 italic">No MITRE mapping available for this rule.</p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'payload' && (
              <div className="animate-fade-in">
                <div className="rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
                  <div className="px-5 py-3 bg-slate-900 flex items-center justify-between">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest leading-none">JSON Event Data</span>
                    <div className="flex items-center gap-4">
                      <button onClick={() => { setActiveTab('ai_explain'); loadAiAnalysis() }} className="text-[10px] text-emerald-300 hover:text-white font-black uppercase tracking-widest">
                        Explain With AI
                      </button>
                      <button onClick={() => navigator.clipboard.writeText(payloadJson)} className="text-[10px] text-sky-400 hover:text-white font-black uppercase tracking-widest">Copy</button>
                    </div>
                  </div>
                  <pre className="p-6 bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto selection:bg-white/10 custom-scrollbar">
                    {payloadJson}
                  </pre>
                </div>
              </div>
            )}

            {activeTab === 'ai_explain' && (
              <div className="animate-fade-in space-y-4">
                <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-800 text-white border border-slate-700">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h3 className="text-base font-black tracking-tight">AI Log Explainer</h3>
                      <p className="text-xs text-slate-300 mt-1">Converts raw event payload into analyst-friendly language.</p>
                    </div>
                    <button
                      onClick={loadAiAnalysis}
                      disabled={aiLoading}
                      className="px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-white/10 hover:bg-white/20 disabled:opacity-60"
                    >
                      {aiLoading ? 'Analyzing...' : 'Refresh'}
                    </button>
                  </div>
                </div>

                {aiLoading && (
                  <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                    <p className="text-sm font-semibold text-slate-500">Analyzing log details...</p>
                  </div>
                )}

                {!aiLoading && aiAnalysis && (
                  <>
                    <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                      <h4 className="text-sm font-black text-slate-900">{aiAnalysis.headline}</h4>
                      <p className="text-sm text-slate-600 mt-2 leading-relaxed">{aiAnalysis.plain_language}</p>
                      <div className="mt-4 flex items-center gap-2">
                        <span className="px-2 py-1 rounded-lg bg-slate-100 text-slate-700 text-[10px] font-black uppercase tracking-widest">
                          Risk: {aiAnalysis.risk_level}
                        </span>
                        <span className="px-2 py-1 rounded-lg bg-sky-100 text-sky-700 text-[10px] font-black uppercase tracking-widest">
                          Confidence: {aiAnalysis.confidence_pct}%
                        </span>
                      </div>
                    </div>

                    <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-3">Key Findings</h4>
                      <div className="space-y-2">
                        {(aiAnalysis.key_findings || []).map((item, idx) => (
                          <p key={`finding-${idx}`} className="text-sm text-slate-700">• {item}</p>
                        ))}
                      </div>
                    </div>

                    <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                      <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-3">Recommended Actions</h4>
                      <div className="space-y-2">
                        {(aiAnalysis.recommended_actions || []).map((item, idx) => (
                          <p key={`action-${idx}`} className="text-sm text-slate-700">• {item}</p>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {activeTab === 'notes' && (
              <div className="flex flex-col h-full animate-fade-in">
                <div className="flex-1 space-y-4 mb-6 pr-2 overflow-y-auto custom-scrollbar">
                  {notes.map(note => (
                    <div key={note.id} className="p-4 rounded-2xl bg-white border border-slate-100 shadow-sm">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-black text-slate-900">{note.author_name}</span>
                        <span className="text-[10px] text-slate-400">{new Date(note.created_at).toLocaleString()}</span>
                      </div>
                      <p className="text-sm text-slate-600 leading-relaxed">{note.note}</p>
                    </div>
                  ))}
                  {notes.length === 0 && (
                    <div className="flex flex-col items-center justify-center py-20 text-slate-300">
                      <span className="material-symbols-outlined text-4xl mb-4">chat_bubble</span>
                      <p className="text-xs font-black uppercase tracking-widest">No analyst notes yet</p>
                    </div>
                  )}
                </div>
                <div className="bg-white p-4 rounded-3xl border border-slate-200 shadow-lg mt-auto">
                  <div className="flex items-end gap-3">
                    <textarea
                      value={newNote}
                      onChange={e => setNewNote(e.target.value)}
                      placeholder="Type official analyst note..."
                      className="flex-1 bg-transparent border-none focus:ring-0 text-sm py-2 resize-none min-h-[40px] max-h-[120px] custom-scrollbar"
                    />
                    <button onClick={addNote} className="w-10 h-10 rounded-2xl bg-slate-900 text-white flex items-center justify-center shadow-xl hover:scale-105 transition-transform active:scale-95">
                      <span className="material-symbols-outlined text-[20px]">send</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'audit' && (
              <div className="space-y-4 animate-fade-in h-full overflow-y-auto pr-2 custom-scrollbar">
                {auditLog.map(log => (
                  <div key={log.id} className="relative pl-10">
                    <div className="absolute left-[19px] top-0 bottom-0 w-0.5 bg-slate-100"></div>
                    <div className="absolute left-0 top-0 w-10 h-10 rounded-full bg-white border-2 border-slate-100 flex items-center justify-center z-10 shadow-sm">
                      <div className="w-3 h-3 rounded-full bg-sky-500 shadow-[0_0_8px] shadow-sky-500/50"></div>
                    </div>
                    <div className="pt-2">
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-black text-slate-900 uppercase tracking-tight">{log.action}</span>
                        <span className="text-[10px] text-slate-400 font-bold">{new Date(log.created_at).toLocaleString()}</span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">Actor: <span className="font-bold text-slate-700">{log.actor_name || 'System'}</span></p>
                      {log.details && Object.keys(log.details).length > 0 && (
                        <div className="mt-3 p-3 rounded-xl bg-slate-50 border border-slate-100 text-[10px] font-mono text-slate-500">
                          {JSON.stringify(log.details, null, 2)}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'enrichment' && (
              <div className="animate-fade-in text-center py-20">
                <div className="w-20 h-20 rounded-full bg-sky-50 flex items-center justify-center text-sky-500 mx-auto mb-6">
                  <span className="material-symbols-outlined text-4xl animate-pulse">hub</span>
                </div>
                <h3 className="text-base font-black text-slate-900">IOC External Correlation</h3>
                <p className="text-sm text-slate-500 mt-2">
                  Quick pivot IOC: <span className="font-bold text-slate-700">{iocForLookup || 'Not found in payload'}</span>
                </p>
                <div className="mt-8 flex justify-center gap-4 flex-wrap">
                  <button
                    onClick={() => openLookupTool('virustotal')}
                    className="px-6 py-4 rounded-2xl bg-white border border-slate-100 shadow-sm hover:border-sky-300 transition-all cursor-pointer"
                  >
                    <div className="w-8 h-8 mx-auto mb-3 rounded-lg bg-sky-50 flex items-center justify-center text-sky-500">
                      <span className="material-symbols-outlined text-[18px]">shield</span>
                    </div>
                    <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">VirusTotal</span>
                  </button>
                  <button
                    onClick={() => openLookupTool('abuseipdb')}
                    className="px-6 py-4 rounded-2xl bg-white border border-slate-100 shadow-sm hover:border-sky-300 transition-all cursor-pointer"
                  >
                    <div className="w-8 h-8 mx-auto mb-3 rounded-lg bg-amber-50 flex items-center justify-center text-amber-500">
                      <span className="material-symbols-outlined text-[18px]">gpp_maybe</span>
                    </div>
                    <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">AbuseIPDB</span>
                  </button>
                  <button
                    onClick={() => openLookupTool('otx')}
                    className="px-6 py-4 rounded-2xl bg-white border border-slate-100 shadow-sm hover:border-sky-300 transition-all cursor-pointer"
                  >
                    <div className="w-8 h-8 mx-auto mb-3 rounded-lg bg-violet-50 flex items-center justify-center text-violet-500">
                      <span className="material-symbols-outlined text-[18px]">travel_explore</span>
                    </div>
                    <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">AlienVault OTX</span>
                  </button>
                </div>
              </div>
            )}

            {activeTab === 'resolve' && (
              <div className="animate-fade-in max-w-lg mx-auto py-10">
                <h3 className="text-lg font-black text-slate-900 mb-6">Finalize Alert Disposition</h3>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 block mb-2">Resolution Outcome</label>
                    <select
                      value={resolution.type}
                      onChange={e => setResolution({ ...resolution, type: e.target.value })}
                      className="w-full px-4 py-3 rounded-2xl bg-white border border-slate-200 text-sm font-bold focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 transition-all"
                    >
                      <option value="true_positive">True Positive (Critical Threat)</option>
                      <option value="false_positive">False Positive (Benign Traffic)</option>
                      <option value="exception">Authorized Exception</option>
                      <option value="mitigated">Mitigated / Remedied</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-black uppercase tracking-widest text-slate-400 block mb-2">Justification Notes</label>
                    <textarea
                      value={resolution.reason}
                      onChange={e => setResolution({ ...resolution, reason: e.target.value })}
                      placeholder="Mandatory analyst reasoning for closure..."
                      className="w-full px-4 py-3 rounded-2xl bg-white border border-slate-200 text-sm min-h-[120px] focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 transition-all"
                    />
                  </div>
                  <button
                    onClick={() => handleAction('resolve')}
                    disabled={loading}
                    className="w-full py-4 rounded-2xl bg-slate-900 text-white font-black text-sm uppercase tracking-widest hover:bg-slate-800 transition-all shadow-xl shadow-slate-900/20 disabled:opacity-60"
                  >
                    Confirm Resolution
                  </button>
                  <button onClick={() => setActiveTab('investigation')} className="w-full py-2 text-xs font-bold text-slate-400 hover:text-slate-600 transition-colors">
                    Back to Investigation
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
