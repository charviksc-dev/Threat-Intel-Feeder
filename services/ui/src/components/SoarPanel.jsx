import { useState, useEffect } from 'react'

export default function SoarPanel({ axiosClient, permissions }) {
  const [activeTab, setActiveTab] = useState('playbooks')
  const [playbooks, setPlaybooks] = useState([])
  const [theHiveCases, setTheHiveCases] = useState([])
  const [cortexAnalyzers, setCortexAnalyzers] = useState([])
  const [failedWebhooks, setFailedWebhooks] = useState([])
  const [loading, setLoading] = useState(true)
  const [executing, setExecuting] = useState(null)
  const [cortexJob, setCortexJob] = useState(null)
  const [observableType, setObservableType] = useState('ip')
  const [observableValue, setObservableValue] = useState('')

  const canExecutePlaybook = permissions?.role === 'admin' || permissions?.role === 'soc_manager' || permissions?.role === 'analyst'
  const canViewAdmin = permissions?.role === 'admin' || permissions?.role === 'soc_manager'

  useEffect(() => {
    fetchData()
  }, [])

  async function fetchData() {
    setLoading(true)
    try {
      const [playbooksRes, casesRes, analyzersRes] = await Promise.all([
        axiosClient.get('/soar/playbooks'),
        axiosClient.get('/soar/cases'),
        axiosClient.get('/soar/cortex/analyzers'),
      ])
      setPlaybooks(playbooksRes.data || [])
      setTheHiveCases(casesRes.data || [])
      setCortexAnalyzers(analyzersRes.data || [])
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function fetchFailedWebhooks() {
    try {
      const res = await axiosClient.get('/soar/webhooks/failed')
      setFailedWebhooks(res.data || [])
    } catch (err) {
      console.error(err)
    }
  }

  async function executePlaybook(playbookId, playbookName) {
    if (!canExecutePlaybook) return
    setExecuting(playbookId)
    try {
      const res = await axiosClient.post(`/soar/playbooks/${playbookId}/execute`)
      alert(`✅ Playbook "${playbookName}" executed successfully!`)
    } catch (err) {
      alert(`❌ Failed to execute playbook: ${err.message}`)
    }
    setExecuting(null)
  }

  async function runCortexAnalysis(analyzerId) {
    if (!canExecutePlaybook || !observableValue) return
    setExecuting(analyzerId)
    try {
      const res = await axiosClient.post('/soar/cortex/analyze', null, {
        params: { analyzer_id: analyzerId, observable_type: observableType, observable_value: observableValue }
      })
      setCortexJob(res.data)
      alert(`🚀 Cortex analysis started: ${res.data.job_id}`)
    } catch (err) {
      alert(`❌ Failed to run analysis: ${err.message}`)
    }
    setExecuting(null)
  }

  async function retryWebhooks() {
    if (!canViewAdmin) return
    try {
      const res = await axiosClient.post('/soar/webhooks/retry')
      alert(`Retried: ${res.data.success} succeeded, ${res.data.failed} failed, ${res.data.remaining} remaining`)
      fetchFailedWebhooks()
    } catch (err) {
      alert(`❌ Retry failed: ${err.message}`)
    }
  }

  if (loading) {
    return <div className="text-center py-20 text-slate-400">Loading SOAR...</div>
  }

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-black text-slate-900 tracking-tight">SOAR Platform</h2>
          <p className="text-sm font-medium text-slate-500 mt-1">
            Orchestrate automated response and enrichment
          </p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-slate-200 pb-4">
        {[
          { id: 'playbooks', label: 'Playbooks', icon: '⚡' },
          { id: 'cases', label: 'TheHive Cases', icon: '📁' },
          { id: 'cortex', label: 'Cortex Analyzers', icon: '🔬' },
          { id: 'dlq', label: 'Webhook DLQ', icon: '📮' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); if (tab.id === 'dlq') fetchFailedWebhooks() }}
            className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${
              activeTab === tab.id 
                ? 'bg-sky-500 text-white shadow-lg shadow-sky-500/20' 
                : 'text-slate-500 hover:bg-slate-100'
            }`}
          >
            <span className="mr-2">{tab.icon}</span>{tab.label}
          </button>
        ))}
      </div>

      {/* Playbooks Tab */}
      {activeTab === 'playbooks' && (
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4">Available Playbooks</h3>
            <p className="text-sm text-slate-500 mb-6">Execute automated response actions on IOCs or cases.</p>
            
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {playbooks.map(pb => (
                <div key={pb.id} className="p-5 rounded-2xl border border-slate-200 bg-white hover:border-sky-300 transition-all">
                  <div className="flex items-start justify-between mb-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center text-white">
                      <span className="material-symbols-outlined text-lg">bolt</span>
                    </div>
                    {canExecutePlaybook && (
                      <button
                        onClick={() => executePlaybook(pb.id, pb.name)}
                        disabled={executing === pb.id}
                        className="px-3 py-1.5 rounded-lg bg-sky-500 text-white text-xs font-bold hover:bg-sky-600 disabled:opacity-50"
                      >
                        {executing === pb.id ? 'Running...' : 'Execute'}
                      </button>
                    )}
                  </div>
                  <h4 className="font-bold text-slate-900 mb-1">{pb.name}</h4>
                  <p className="text-xs text-slate-500">{pb.description}</p>
                  {pb.requires && (
                    <div className="mt-3 pt-3 border-t border-slate-100">
                      <span className="text-[10px] font-bold text-slate-400 uppercase">Requires: </span>
                      <span className="text-[10px] font-bold text-sky-500">{pb.requires}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TheHive Cases Tab */}
      {activeTab === 'cases' && (
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-slate-900">TheHive Cases</h3>
              <button onClick={fetchData} className="text-sm text-sky-500 font-bold hover:underline">Refresh</button>
            </div>
            <p className="text-sm text-slate-500 mb-4">Bidirectional sync with TheHive for case status.</p>
            
            {theHiveCases.length === 0 ? (
              <div className="text-center py-12 text-slate-400">
                <span className="material-symbols-outlined text-4xl mb-2">folder_off</span>
                <p className="text-sm">No cases found. Configure THEHIVE_URL in .env</p>
              </div>
            ) : (
              <div className="space-y-3">
                {theHiveCases.slice(0, 10).map(c => (
                  <div key={c.case_id} className="flex items-center justify-between p-4 rounded-xl bg-slate-50 border border-slate-100">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        c.status === 'Resolved' ? 'bg-emerald-500' : 'bg-amber-500'
                      }`}></div>
                      <div>
                        <div className="text-sm font-bold text-slate-800">{c.title}</div>
                        <div className="text-xs text-slate-400">ID: {c.case_id}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs font-bold text-slate-500">Severity {c.severity}</div>
                      <div className="text-[10px] text-slate-400">{c.created_at?.slice(0,10)}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Cortex Analyzers Tab */}
      {activeTab === 'cortex' && (
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4">Cortex Analyzers</h3>
            <p className="text-sm text-slate-500 mb-6">Enrich observables with threat intelligence from Cortex.</p>
            
            {/* Analysis Input */}
            <div className="mb-6 p-4 rounded-xl bg-slate-50 border border-slate-200">
              <div className="flex gap-3 flex-wrap">
                <select 
                  value={observableType} 
                  onChange={e => setObservableType(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-slate-200 text-sm"
                >
                  <option value="ip">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="hash">Hash</option>
                  <option value="file">File</option>
                </select>
                <input
                  type="text"
                  value={observableValue}
                  onChange={e => setObservableValue(e.target.value)}
                  placeholder="Enter observable value..."
                  className="flex-1 px-3 py-2 rounded-lg border border-slate-200 text-sm min-w-[200px]"
                />
              </div>
              <div className="flex gap-2 mt-3 flex-wrap">
                {cortexAnalyzers.slice(0, 4).map(a => (
                  <button
                    key={a.id}
                    onClick={() => runCortexAnalysis(a.id)}
                    disabled={!canExecutePlaybook || !observableValue || executing === a.id}
                    className="px-3 py-1.5 rounded-lg bg-purple-500 text-white text-xs font-bold hover:bg-purple-600 disabled:opacity-50"
                  >
                    {executing === a.id ? 'Running...' : `Run ${a.name}`}
                  </button>
                ))}
              </div>
            </div>

            {/* Results */}
            {cortexJob && (
              <div className="mt-4 p-4 rounded-xl bg-purple-50 border border-purple-200">
                <div className="flex items-center gap-2 mb-2">
                  <span className="material-symbols-outlined text-purple-500">science</span>
                  <span className="font-bold text-purple-700">Analysis Started</span>
                </div>
                <div className="text-sm text-purple-600">Job ID: {cortexJob.job_id}</div>
                <div className="text-xs text-purple-400 mt-1">Check job status via /soar/cortex/job/{job_id}</div>
              </div>
            )}

            {/* Available Analyzers */}
            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3 mt-6">
              {cortexAnalyzers.map(a => (
                <div key={a.id} className="p-4 rounded-xl bg-white border border-slate-200">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-lg">🔬</span>
                    <span className="font-bold text-slate-800 text-sm">{a.name}</span>
                  </div>
                  <p className="text-xs text-slate-500 line-clamp-2">{a.description}</p>
                  <div className="mt-2 flex gap-1 flex-wrap">
                    {(a.data_types || []).slice(0, 3).map(t => (
                      <span key={t} className="px-1.5 py-0.5 rounded bg-slate-100 text-[9px] font-bold text-slate-500">{t}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* DLQ Tab */}
      {activeTab === 'dlq' && (
        <div className="space-y-6">
          <div className="glass-panel p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-slate-900">Webhook Dead Letter Queue</h3>
                <p className="text-sm text-slate-500">Failed webhooks with retry logic (max 3 retries)</p>
              </div>
              {canViewAdmin && (
                <button
                  onClick={retryWebhooks}
                  className="px-4 py-2 rounded-lg bg-rose-500 text-white text-sm font-bold hover:bg-rose-600"
                >
                  Retry All
                </button>
              )}
            </div>

            {failedWebhooks.length === 0 ? (
              <div className="text-center py-12 text-slate-400">
                <span className="material-symbols-outlined text-4xl mb-2">check_circle</span>
                <p className="text-sm">No failed webhooks - all caught up!</p>
              </div>
            ) : (
              <div className="space-y-3">
                {failedWebhooks.map((fw, i) => (
                  <div key={i} className="p-4 rounded-xl bg-rose-50 border border-rose-100">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-bold text-rose-700">{fw.operation}</div>
                        <div className="text-xs text-rose-500">Error: {fw.error}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-xs text-rose-400">Retries: {fw.retries}/3</div>
                        <div className="text-[10px] text-rose-300">{fw.timestamp}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}