import { useState, useEffect } from 'react'

export default function SourcesPanel({ axiosClient, permissions }) {
  const [sources, setSources] = useState([])
  const [feedHealth, setFeedHealth] = useState([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(null)
  const [syncResult, setSyncResult] = useState(null)
  const [selectedFeed, setSelectedFeed] = useState("")
  const canTriggerFeedSync = Boolean(permissions?.triggerFeedSync)

  useEffect(() => {
    fetchSources()
    fetchFeedHealth()
  }, [])

  async function fetchSources() {
    try {
      const res = await axiosClient.get('/sources')
      setSources(res.data)
    } catch {
      setSources([])
    }
    setLoading(false)
  }

  async function fetchFeedHealth() {
    try {
      const res = await axiosClient.get('/feeds/health')
      setFeedHealth(res.data || [])
    } catch {
      setFeedHealth([])
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
    <div className="space-y-8 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-black text-slate-900 tracking-tight">Intelligence Hub</h2>
          <p className="text-sm font-medium text-slate-500 mt-1">
            <span className="text-sky-600 font-bold">{sources.length} Verified Sources</span> currently providing real-time data
          </p>
        </div>
        <button
          onClick={fetchSources}
          className="w-10 h-10 rounded-xl bg-slate-100 flex items-center justify-center text-slate-500 hover:bg-sky-500 hover:text-white transition-all shadow-inner border border-slate-200"
          title="Rescan Nodes"
        >
          <span className="material-symbols-outlined text-[20px] animate-hover-pulse">sync</span>
        </button>
      </div>

      {/* Sync Interface - Premium Controls */}
      <div className="glass-panel p-6 flex flex-col md:flex-row items-center gap-4 border-sky-100/50 shadow-xl shadow-sky-500/5">
        <div className="flex-1 w-full relative group">
          <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-sky-500 transition-colors">hub</span>
          <select
            value={selectedFeed}
            onChange={(e) => setSelectedFeed(e.target.value)}
            className="input pl-12 py-3.5 text-xs font-black uppercase tracking-widest appearance-none cursor-pointer bg-white"
          >
            <option value="">Authorize Feed Synchronization...</option>
            {FEEDS.map((feed) => (
              <option key={feed.name} value={feed.name}>
                {feed.label}
              </option>
            ))}
          </select>
          <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400">
            <span className="material-symbols-outlined text-[20px]">expand_more</span>
          </div>
        </div>
        <button
          onClick={handleSync}
          disabled={!canTriggerFeedSync || !selectedFeed || syncing}
          className="btn btn-primary px-8 py-3.5 text-xs font-black uppercase tracking-widest shadow-2xl shadow-sky-500/20 active:scale-95 disabled:opacity-40"
        >
          {syncing ? (
            <span className="flex items-center gap-2">
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>
              In Progress
            </span>
          ) : 'Execute Sync'}
        </button>
      </div>
      {!canTriggerFeedSync && (
        <div className="p-4 rounded-2xl border border-amber-200 bg-amber-50 text-amber-700 text-xs font-semibold">
          RBAC policy: feed synchronization is restricted to `soc_manager` and `admin`.
        </div>
      )}

      {/* Sync Status Notify */}
      {syncResult && (
        <div className={`p-4 rounded-2xl flex items-center gap-4 border animate-in slide-in-from-top-4 ${
          syncResult.status === 'error' ? 'bg-rose-50 border-rose-100 text-rose-700' : 'bg-sky-50 border-sky-100 text-sky-700'
        }`}>
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-xl shrink-0 ${
            syncResult.status === 'error' ? 'bg-rose-100' : 'bg-sky-100'
          }`}>
            <span className="material-symbols-outlined">{syncResult.status === 'error' ? 'error' : 'info'}</span>
          </div>
          <code className="text-xs font-bold leading-relaxed">{syncResult.message}</code>
        </div>
      )}

      {/* Grid of All Available Feeds - Immersive Cards */}
      <div className="space-y-4">
        <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] ml-1">Threat Infrastructure Grid</h3>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {FEEDS.map((feed) => {
            const isActive = sources.includes(feed.name)
            const health = feedHealth.find(h => h.feed_name === feed.name)
            const status = health?.status || (isActive ? 'active' : 'standby')
            const lastIngested = health?.last_ingested_at ? new Date(health.last_ingested_at) : null
            const now = new Date()
            const hoursAgo = lastIngested ? Math.floor((now - lastIngested) / (1000 * 60 * 60)) : null
            const isStale = status === 'stale' || (hoursAgo !== null && hoursAgo > 24)
            
            return (
              <div
                key={feed.name}
                className={`group relative p-5 rounded-3xl border transition-all duration-300 ${
                  isActive
                    ? 'bg-white border-emerald-200 shadow-xl shadow-emerald-500/5'
                    : 'bg-white/50 border-slate-200 hover:border-sky-300'
                }`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-2xl shadow-inner border group-hover:scale-110 transition-transform ${
                    isActive ? 'bg-emerald-50 border-emerald-100' : 'bg-slate-50 border-slate-100'
                  }`}>
                    {feed.icon}
                  </div>
                  {status === 'active' || status === 'stale' ? (
                    <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-widest border ${
                      isStale 
                        ? 'bg-amber-500/10 text-amber-600 border-amber-500/20' 
                        : 'bg-emerald-500/10 text-emerald-600 border-emerald-500/10'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${isStale ? 'bg-amber-500' : 'bg-emerald-500 animate-pulse'}`}></span>
                      {isStale ? 'Stale' : 'Active'}
                    </span>
                  ) : status === 'error' ? (
                    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-500/10 text-[9px] font-black text-rose-600 uppercase tracking-widest border border-rose-500/20">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                      Error
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-full bg-slate-100 text-[9px] font-black text-slate-400 uppercase tracking-widest border border-slate-100">Standby</span>
                  )}
                </div>

                <div className="space-y-1">
                  <h4 className="font-black text-slate-900 tracking-tight">{feed.label}</h4>
                  <div className="flex items-center gap-2">
                    <span className={`text-[8px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded ${
                      feed.type === 'free' ? 'bg-sky-50 text-sky-600' : feed.type === 'api-key' ? 'bg-amber-50 text-amber-600' : 'bg-purple-50 text-purple-600'
                    }`}>
                      {feed.type} protocol
                    </span>
                  </div>
                </div>

                {/* Health Metrics */}
                {health && (
                  <div className="mt-3 pt-3 border-t border-slate-100 space-y-1.5">
                    {health.ioc_count > 0 && (
                      <div className="flex items-center justify-between text-[9px]">
                        <span className="text-slate-400 font-medium uppercase tracking-wider">IOCs</span>
                        <span className="font-black text-slate-600">{health.ioc_count.toLocaleString()}</span>
                      </div>
                    )}
                    {hoursAgo !== null && (
                      <div className="flex items-center justify-between text-[9px]">
                        <span className="text-slate-400 font-medium uppercase tracking-wider">Last Sync</span>
                        <span className={`font-bold ${isStale ? 'text-amber-600' : 'text-slate-600'}`}>
                          {hoursAgo < 1 ? '<1h' : hoursAgo < 24 ? `${hoursAgo}h` : `${Math.floor(hoursAgo/24)}d`}
                        </span>
                      </div>
                    )}
                    {health.consecutive_failures > 0 && (
                      <div className="flex items-center justify-between text-[9px]">
                        <span className="text-slate-400 font-medium uppercase tracking-wider">Errors</span>
                        <span className="font-bold text-rose-600">{health.consecutive_failures} retries</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Glow effect on hover */}
                <div className="absolute inset-0 rounded-3xl bg-sky-500/0 group-hover:bg-sky-500/[0.02] transition-colors pointer-events-none"></div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Admin Operations - CLI Reference Panel */}
      <div className="glass-panel p-8 relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-32 h-32 bg-slate-900/5 rounded-full blur-3xl -mr-16 -mt-16"></div>
        
        <div className="flex items-center gap-6 mb-6">
          <div className="w-14 h-14 rounded-2xl bg-slate-900 flex items-center justify-center text-white border border-slate-800 shadow-xl shadow-slate-900/20">
            <span className="material-symbols-outlined text-emerald-400">terminal</span>
          </div>
          <div>
            <h3 className="text-xl font-black text-slate-900 tracking-tight">Manual Ingestion Controls</h3>
            <p className="text-sm font-medium text-slate-500">Bypass the UI engine with administrative CLI commands</p>
          </div>
        </div>

        <div className="bg-[#020617] rounded-3xl p-6 text-[11px] font-mono shadow-2xl border border-white/5 space-y-4 relative group/terminal">
          <div className="absolute top-4 right-4 text-[9px] font-black text-slate-700 uppercase tracking-[0.2em] opacity-40">System Bash</div>
          
          <div className="space-y-3">
            <div className="opacity-50 text-slate-400 text-[10px] font-black uppercase tracking-widest mb-1"># Bulk Synchronization</div>
            <div className="flex items-center gap-3 group/cmd">
              <span className="text-sky-500 font-bold">$</span>
              <code className="text-emerald-400">docker compose exec worker celery -A app.celery_app call worker.sync.all</code>
              <button 
                onClick={() => navigator.clipboard.writeText("docker compose exec worker celery -A app.celery_app call worker.sync.all")}
                className="ml-auto p-1.5 hover:bg-white/10 rounded transition-colors text-slate-600 hover:text-white"
              >
                <span className="material-symbols-outlined text-[14px]">content_copy</span>
              </button>
            </div>
          </div>

          <div className="space-y-2 pt-2">
            <div className="opacity-50 text-slate-400 text-[10px] font-black uppercase tracking-widest mb-1"># Atomic Source Ingestion</div>
            {FEEDS.slice(0, 4).map(f => (
              <div key={f.name} className="flex items-center gap-3">
                <span className="text-sky-500/50">$</span>
                <code className="text-slate-300">celery call {f.task}</code>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
