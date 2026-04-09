import { useState, useEffect } from 'react'

export default function AlertDetailModal({ alert, axiosClient, onClose, onRefresh }) {
  const [activeTab, setActiveTab] = useState('investigation')
  const [notes, setNotes] = useState([])
  const [auditLog, setAuditLog] = useState([])
  const [newNote, setNewNote] = useState('')
  const [loading, setLoading] = useState(false)
  const [resolution, setResolution] = useState({ type: 'true_positive', reason: '' })

  useEffect(() => {
    if (alert) {
      fetchData()
    }
  }, [alert])

  async function fetchData() {
    try {
      const [notesRes, auditRes] = await Promise.all([
        axiosClient.get(`/alerts/${alert.alert_id}/notes`),
        axiosClient.get(`/alerts/${alert.alert_id}/audit`)
      ])
      setNotes(notesRes.data)
      setAuditLog(auditRes.data)
    } catch (err) {
      console.error('Failed to fetch alert details', err)
    }
  }

  async function handleAction(action) {
    setLoading(true)
    try {
      if (action === 'acknowledge') {
        await axiosClient.post(`/alerts/${alert.alert_id}/acknowledge`)
      } else if (action === 'resolve') {
        await axiosClient.post(`/alerts/${alert.alert_id}/resolve`, {
          status: 'resolved',
          resolution_type: resolution.type,
          reason: resolution.reason
        })
      }
      onRefresh?.()
      fetchData()
    } catch (err) {
      console.error(`Action ${action} failed`, err)
    }
    setLoading(false)
  }

  async function addNote() {
    if (!newNote.trim()) return
    try {
      await axiosClient.post(`/alerts/${alert.alert_id}/notes`, { note: newNote })
      setNewNote('')
      fetchData()
    } catch (err) {
      console.error('Failed to add note', err)
    }
  }

  const severityColors = {
    critical: 'bg-rose-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-sky-500'
  }

  const statusColors = {
    new: 'bg-blue-500',
    acknowledged: 'bg-amber-500',
    resolved: 'bg-emerald-500',
    closed: 'bg-slate-500'
  }

  if (!alert) return null

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-fade-in">
      <div className="bg-white w-full max-w-5xl h-[85vh] rounded-3xl shadow-2xl overflow-hidden flex flex-col animate-scale-up">
        {/* Header */}
        <div className="px-8 py-6 border-b border-slate-100 bg-slate-50/50 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-2xl ${severityColors[alert.severity] || 'bg-slate-500'} flex items-center justify-center text-white shadow-lg`}>
              <span className="material-symbols-outlined text-2xl">warning</span>
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-black text-slate-900 tracking-tight">{alert.source} Alert</h2>
                <span className={`text-[10px] font-black uppercase tracking-widest px-2.5 py-1 rounded-lg text-white ${statusColors[alert.status] || 'bg-slate-500'}`}>
                  {alert.status}
                </span>
              </div>
              <p className="text-xs text-slate-500 font-mono mt-1">ID: {alert.alert_id}</p>
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
                 {alert.status === 'new' && (
                   <button 
                    onClick={() => handleAction('acknowledge')}
                    disabled={loading}
                    className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-amber-50 text-amber-600 border border-amber-100 hover:bg-amber-100 transition-all font-bold text-sm shadow-sm"
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
                 <button className="w-full flex items-center gap-3 px-4 py-3 rounded-2xl bg-sky-50 text-sky-600 border border-sky-100 hover:bg-sky-100 transition-all font-bold text-sm shadow-sm">
                   <span className="material-symbols-outlined text-[18px]">person_add</span>
                   Assign to...
                 </button>
               </div>
             </div>

             <nav className="space-y-1">
               <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400 mb-4">Investigation</h3>
               {[
                 { id: 'investigation', label: 'Summary', icon: 'info' },
                 { id: 'payload', label: 'Raw Payload', icon: 'code' },
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
                    <p className="text-sm font-bold text-slate-800">{alert.source}</p>
                    <p className="text-[10px] text-slate-500 mt-1">Rule ID: {alert.payload?.rule?.id || 'N/A'}</p>
                  </div>
                  <div className="p-5 rounded-2xl bg-white border border-slate-100 shadow-sm">
                    <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-2">Confidence Score</h4>
                    <div className="flex items-center gap-2">
                       <span className="text-xl font-black text-slate-900">{alert.severity === 'critical' ? '95%' : alert.severity === 'high' ? '80%' : '60%'}</span>
                       <div className="w-24 h-2 bg-slate-100 rounded-full overflow-hidden">
                         <div className={`h-full ${severityColors[alert.severity]} rounded-full`} style={{ width: alert.severity === 'critical' ? '95%' : '80%' }}></div>
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
                      <p className="text-sm font-bold text-slate-800">{alert.payload?.agent?.name || 'Unknown Host'}</p>
                      <p className="text-[10px] text-slate-500">IP: {alert.payload?.agent?.ip || 'N/A'} • OS: {alert.payload?.agent?.os?.name || 'Unknown'}</p>
                    </div>
                  </div>
                </div>

                <div className="p-6 rounded-2xl bg-white border border-slate-100 shadow-sm">
                  <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-400 mb-4">MITRE ATT&CK Mapping</h4>
                  <div className="flex flex-wrap gap-2">
                    {alert.payload?.rule?.mitre?.id?.map(id => (
                      <span key={id} className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-sky-50 text-sky-600 text-[10px] font-black border border-sky-100 uppercase tracking-tight">
                        <span className="material-symbols-outlined text-[12px]">rebase_edit</span>
                        {id}
                      </span>
                    ))}
                    {(!alert.payload?.rule?.mitre?.id || alert.payload?.rule?.mitre?.id.length === 0) && (
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
                    <button onClick={() => navigator.clipboard.writeText(JSON.stringify(alert.payload, null, 2))} className="text-[10px] text-sky-400 hover:text-white font-black uppercase tracking-widest">Copy</button>
                  </div>
                  <pre className="p-6 bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto selection:bg-white/10 custom-scrollbar">
                    {JSON.stringify(alert.payload, null, 2)}
                  </pre>
                </div>
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
                {auditLog.map((log, idx) => (
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
                <p className="text-sm text-slate-500 mt-2">Correlation engine indexing historical context...</p>
                <div className="mt-8 flex justify-center gap-4">
                  <div className="px-6 py-4 rounded-2xl bg-white border border-slate-100 shadow-sm hover:border-sky-300 transition-all cursor-pointer">
                    <img src="https://www.google.com/s2/favicons?domain=virustotal.com&sz=64" className="w-8 h-8 mx-auto mb-3 opacity-60 grayscale group-hover:grayscale-0" />
                    <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">VirusTotal</span>
                  </div>
                  <div className="px-6 py-4 rounded-2xl bg-white border border-slate-100 shadow-sm hover:border-sky-300 transition-all cursor-pointer">
                    <img src="https://www.google.com/s2/favicons?domain=shodan.io&sz=64" className="w-8 h-8 mx-auto mb-3 opacity-60 grayscale" />
                    <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Shodan</span>
                  </div>
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
                      onChange={e => setResolution({...resolution, type: e.target.value})}
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
                      onChange={e => setResolution({...resolution, reason: e.target.value})}
                      placeholder="Mandatory analyst reasoning for closure..."
                      className="w-full px-4 py-3 rounded-2xl bg-white border border-slate-200 text-sm min-h-[120px] focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 transition-all"
                    />
                  </div>
                  <button 
                    onClick={() => handleAction('resolve')}
                    className="w-full py-4 rounded-2xl bg-slate-900 text-white font-black text-sm uppercase tracking-widest hover:bg-slate-800 transition-all shadow-xl shadow-slate-900/20"
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
