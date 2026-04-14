import { useState, useEffect } from 'react'

export default function SourcesPanel({ axiosClient, permissions }) {
  const [sources, setSources] = useState([])
  const [feedHealth, setFeedHealth] = useState([])
  const [retentionPolicies, setRetentionPolicies] = useState([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('health') // 'health' or 'retention'
  const [syncing, setSyncing] = useState(null)
  const [syncResult, setSyncResult] = useState(null)
  const [selectedFeed, setSelectedFeed] = useState("")

  const canTriggerFeedSync = Boolean(permissions?.triggerFeedSync)

  useEffect(() => {
    fetchSources()
    fetchFeedHealth()
    fetchRetentionPolicies()
  }, [])

  function normalizeSourcesPayload(payload) {
    if (Array.isArray(payload)) return payload
    if (Array.isArray(payload?.sources)) return payload.sources
    return []
  }

  function normalizeFeedHealthPayload(payload) {
    if (Array.isArray(payload)) return payload
    if (Array.isArray(payload?.feeds)) return payload.feeds
    return []
  }

  async function fetchSources() {
    try {
      const res = await axiosClient.get('/sources')
      setSources(normalizeSourcesPayload(res.data))
    } catch {
      setSources([])
    }
    setLoading(false)
  }

  async function fetchFeedHealth() {
    try {
      const res = await axiosClient.get('/feeds/health')
      setFeedHealth(normalizeFeedHealthPayload(res.data))
    } catch {
      setFeedHealth([])
    }
  }

  async function fetchRetentionPolicies() {
    try {
      const res = await axiosClient.get('/admin/retention-policies')
      setRetentionPolicies(res.data)
    } catch (err) {
      console.error('Failed to fetch retention policies:', err)
    }
  }

  async function handleUpdatePolicy(e, feedId) {
    const ttl = e.target.value
    try {
      await axiosClient.post('/admin/retention-policies', {
        feed_id: feedId,
        ttl_days: parseInt(ttl),
        auto_retire: true
      })
      fetchRetentionPolicies()
    } catch (err) {
      console.error('Failed to update policy:', err)
    }
  }

  const FEEDS = [
    { name: 'urlhaus', label: 'URLhaus (Abuse.ch)', task: 'worker.ingest.urlhaus', type: 'free', icon: '🔗' },
    { name: 'threatfox', label: 'ThreatFox (Abuse.ch)', task: 'worker.ingest.threatfox', type: 'free', icon: '🦊' },
    { name: 'feodo-tracker', label: 'Feodo Tracker', task: 'worker.ingest.feodo', type: 'free', icon: '🤖' },
    { name: 'emerging-threats', label: 'Emerging Threats', task: 'worker.ingest.emerging_threats', type: 'free', icon: '⚡' },
    { name: 'abusech', label: 'Abuse.ch CSV', task: 'worker.ingest.abusech', type: 'free', icon: '📋' },
    { name: 'otx', label: 'AlienVault OTX', task: 'worker.ingest.otx', type: 'api-key', icon: '👽' },
    { name: 'virustotal', label: 'VirusTotal', task: 'worker.ingest.virustotal', type: 'api-key', icon: '🔬' },
    { name: 'misp', label: 'MISP (Local)', task: 'worker.ingest.misp', type: 'config', icon: '🔄' },
  ]

  async function handleSync() {
    if (!canTriggerFeedSync) {
      setSyncResult({ status: 'error', message: 'RBAC: Feed sync requires SOC Manager or Administrator role.' })
      return
    }
    if (!selectedFeed) return
    const feed = FEEDS.find(f => f.name === selectedFeed)
    if (!feed) return
    
    setSyncing(selectedFeed)
    setSyncResult(null)
    try {
      const res = await axiosClient.post('/feeds/sync', { task_name: feed.task })
      setSyncResult({
        status: 'info',
        message: `✅ Background task started: ${res.data.message}`,
      })
    } catch (err) {
      setSyncResult({ status: 'error', message: err.response?.data?.detail || err.message })
    }
    setSyncing(null)
  }

  return (
    <div className="space-y-8 animate-fade-in relative pb-10">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div>
          <h2 className="text-3xl font-black text-slate-900 tracking-tight">Intelligence Operations</h2>
          <div className="flex items-center gap-3 mt-1.5">
            <span className="flex items-center gap-1.5 px-3 py-1 bg-emerald-50 text-emerald-600 rounded-lg text-[10px] font-black uppercase tracking-widest border border-emerald-100">
              {sources.length} Active Nodes
            </span>
            <div className="w-1 h-1 rounded-full bg-slate-300"></div>
            <p className="text-sm font-medium text-slate-500">Global feed health and retention lifecycle control</p>
          </div>
        </div>
        <div className="flex items-center p-1 bg-slate-100 rounded-2xl border border-slate-200">
          <button 
            onClick={() => setActiveTab('health')}
            className={`px-6 py-2.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all ${
              activeTab === 'health' ? 'bg-white text-slate-900 shadow-lg border border-slate-200' : 'text-slate-500 hover:text-slate-700'
            }`}
          >
            Connectivity Hub
          </button>
          <button 
            onClick={() => setActiveTab('retention')}
            className={`px-6 py-2.5 rounded-xl text-[11px] font-black uppercase tracking-widest transition-all ${
              activeTab === 'retention' ? 'bg-white text-slate-900 shadow-lg border border-slate-200' : 'text-slate-500 hover:text-slate-700'
            }`}
          >
            Retention Lifecycle
          </button>
        </div>
      </div>

      {activeTab === 'health' ? (
        <>
          {/* Sync Interface */}
          <div className="glass-panel p-8 flex flex-col md:flex-row items-center gap-6 relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-32 h-32 bg-sky-500/5 rounded-full blur-3xl -mr-16 -mt-16"></div>
            <div className="flex-1 w-full relative">
              <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">sensors</span>
              <select
                value={selectedFeed}
                onChange={(e) => setSelectedFeed(e.target.value)}
                className="input pl-12 py-4 text-xs font-black uppercase tracking-widest appearance-none cursor-pointer bg-slate-50/50 border-slate-200 outline-none focus:ring-2 focus:ring-sky-500 transition-all"
              >
                <option value="">Authorize manual feed ingestion protocol...</option>
                {FEEDS.map((feed) => (
                  <option key={feed.name} value={feed.name}>{feed.label}</option>
                ))}
              </select>
            </div>
            <button
              onClick={handleSync}
              disabled={!canTriggerFeedSync || !selectedFeed || syncing}
              className="px-10 py-4 bg-[#020617] text-white rounded-[18px] text-[11px] font-black uppercase tracking-widest hover:bg-sky-600 disabled:opacity-40 transition-all active:scale-95 shadow-2xl shadow-slate-900/20"
            >
              {syncing ? 'Synchronizing...' : 'Execute Ingestion'}
            </button>
          </div>

          {syncResult && (
            <div className={`p-6 rounded-3xl border flex items-center gap-5 slide-in-bottom ${
              syncResult.status === 'error' ? 'bg-rose-50 border-rose-200 text-rose-700' : 'bg-sky-50 border-sky-200 text-sky-700'
            }`}>
              <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-2xl ${
                syncResult.status === 'error' ? 'bg-rose-200' : 'bg-sky-200'
              }`}>
                <span className="material-symbols-outlined">{syncResult.status === 'error' ? 'warning' : 'info'}</span>
              </div>
              <div className="font-mono text-[11px] font-bold">{syncResult.message}</div>
            </div>
          )}

          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {FEEDS.map((feed) => {
              const isActive = sources.includes(feed.name)
              const health = feedHealth.find(h => h.feed_name === feed.name)
              const status = health?.status || (isActive ? 'active' : 'standby') || 'standby'
              const lastIngested = health?.last_ingested_at ? new Date(health.last_ingested_at) : null
              const hoursAgo = lastIngested ? Math.floor((new Date() - lastIngested) / (1000 * 60 * 60)) : null
              const isStale = status === 'stale' || (hoursAgo !== null && hoursAgo > 24)
              
              return (
                <div key={feed.name} className="group glass-panel p-6 border-slate-200 hover:border-sky-300 transition-all duration-500 hover:shadow-2xl hover:shadow-sky-500/5">
                  <div className="flex items-center justify-between mb-5">
                    <div className="w-12 h-12 rounded-2xl bg-slate-50 border border-slate-100 flex items-center justify-center text-3xl group-hover:scale-110 group-hover:rotate-3 transition-all duration-500">
                      {feed.icon}
                    </div>
                    <span className={`px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest border ${
                      status === 'active' && !isStale ? 'bg-emerald-50 text-emerald-600 border-emerald-100' :
                      isStale ? 'bg-amber-50 text-amber-600 border-amber-100' :
                      status === 'error' ? 'bg-rose-50 text-rose-600 border-rose-100' : 'bg-slate-50 text-slate-400 border-slate-100'
                    }`}>
                      {isStale ? 'Stale' : (status || 'Standby')}
                    </span>
                  </div>
                  <h4 className="font-black text-slate-900 mb-1 tracking-tight">{feed.label}</h4>
                  <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-4">{feed.type} protocol</p>
                  
                  {health && (
                    <div className="space-y-3 pt-4 border-t border-slate-50">
                      <div className="flex justify-between items-center text-[10px] font-bold">
                        <span className="text-slate-400 uppercase tracking-widest">Active Intelligence</span>
                        <span className="text-slate-900">{health?.ioc_count?.toLocaleString() || 0} IOCs</span>
                      </div>
                      <div className="flex justify-between items-center text-[10px] font-bold">
                        <span className="text-slate-400 uppercase tracking-widest">Temporal Age</span>
                        <span className={isStale ? 'text-amber-600' : 'text-slate-900'}>
                          {hoursAgo !== null ? `${hoursAgo}h ago` : 'Neutral'}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      ) : (
        <div className="space-y-8 animate-in slide-in-from-right-10 duration-500">
           <div className="glass-panel p-8 bg-amber-50/30 border-amber-200/50">
             <div className="flex items-center gap-5">
               <div className="w-14 h-14 rounded-2xl bg-amber-500 text-white flex items-center justify-center text-2xl shadow-xl shadow-amber-500/20">
                 <span className="material-symbols-outlined">auto_delete</span>
               </div>
               <div>
                 <h3 className="text-xl font-black text-slate-900 tracking-tight">Active Retention Rules</h3>
                 <p className="text-sm font-medium text-slate-600">Configure time-to-live (TTL) for each intelligence stream to prevent dataset bloat and alert fatigue</p>
               </div>
             </div>
           </div>

           <div className="grid gap-6">
             {FEEDS.map(f => {
               const policy = retentionPolicies.find(p => p.feed_id === f.name)
               const ttl = policy?.ttl_days || 30
               return (
                 <div key={f.name} className="glass-panel p-8 flex flex-col md:flex-row md:items-center justify-between gap-8 group hover:border-amber-300 transition-all">
                    <div className="flex items-center gap-6">
                      <div className="w-16 h-16 rounded-3xl bg-white border border-slate-100 flex items-center justify-center text-3xl shadow-sm group-hover:scale-110 transition-transform">
                        {f.icon}
                      </div>
                      <div>
                        <h4 className="text-lg font-black text-slate-900 tracking-tight">{f.label}</h4>
                        <div className="flex items-center gap-3 mt-1">
                          <span className="px-2 py-0.5 bg-slate-900 text-white text-[9px] font-black uppercase tracking-widest rounded">Source ID: {f.name}</span>
                          <span className="text-[11px] font-bold text-slate-400 flex items-center gap-1">
                            <span className="material-symbols-outlined text-[14px]">bolt</span>
                            Auto-retire enabled
                          </span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex flex-col gap-2 min-w-[200px]">
                      <div className="flex items-center justify-between px-1">
                        <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Lifespan Threshold</label>
                        <span className="text-xs font-black text-amber-600">{ttl} Days</span>
                      </div>
                      <input 
                        type="range" 
                        min="1" 
                        max="365" 
                        value={ttl} 
                        onChange={(e) => handleUpdatePolicy(e, f.name)}
                        className="w-full h-2 bg-slate-100 rounded-lg appearance-none cursor-pointer accent-amber-500" 
                      />
                      <div className="flex justify-between text-[9px] font-bold text-slate-300 uppercase tracking-tighter">
                        <span>1 Day</span>
                        <span>6 Months</span>
                        <span>1 Year</span>
                      </div>
                    </div>
                 </div>
               )
             })}
           </div>
        </div>
      )}

      {/* Manual Ingestion Controls - Bash Reference */}
      <div className="glass-panel p-8 mt-12 relative overflow-hidden group bg-slate-900">
        <div className="absolute top-0 right-0 w-64 h-64 bg-sky-500/5 rounded-full blur-[80px] -mr-32 -mt-32"></div>
        <div className="flex items-center gap-6 mb-8 relative z-10">
          <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-emerald-400 shadow-2xl">
            <span className="material-symbols-outlined">terminal</span>
          </div>
          <div>
             <h3 className="text-xl font-black text-white tracking-tight">Intelligence Orchestration CLI</h3>
             <p className="text-sm font-medium text-slate-400">Direct engine controls for administrative overrides</p>
          </div>
        </div>
        <div className="bg-black/50 rounded-2xl p-6 font-mono text-[11px] border border-white/5 relative group/terminal">
           <div className="flex items-center gap-3 mb-4">
             <span className="w-3 h-3 rounded-full bg-rose-500/20"></span>
             <span className="w-3 h-3 rounded-full bg-amber-500/20"></span>
             <span className="w-3 h-3 rounded-full bg-emerald-500/20"></span>
             <span className="ml-2 text-slate-600 font-bold uppercase tracking-widest text-[9px]">Restricted Shell</span>
           </div>
           <div className="space-y-4">
             <div className="flex items-center gap-4 group/cmd">
                <span className="text-slate-700 shrink-0">root@neev:~#</span>
                <code className="text-sky-400">celery -A app.celery_app call worker.sync.all</code>
                <button 
                  onClick={() => navigator.clipboard.writeText("celery -A app.celery_app call worker.sync.all")}
                  className="ml-auto text-slate-600 hover:text-white transition-colors"
                >
                  <span className="material-symbols-outlined text-[16px]">content_copy</span>
                </button>
             </div>
             <div className="flex items-center gap-4 group/cmd">
                <span className="text-slate-700 shrink-0">root@neev:~#</span>
                <code className="text-amber-400">celery -A app.celery_app call worker.lifecycle.retire</code>
                <button 
                  onClick={() => navigator.clipboard.writeText("celery -A app.celery_app call worker.lifecycle.retire")}
                  className="ml-auto text-slate-600 hover:text-white transition-colors"
                >
                  <span className="material-symbols-outlined text-[16px]">content_copy</span>
                </button>
             </div>
           </div>
        </div>
      </div>
    </div>
  )
}
