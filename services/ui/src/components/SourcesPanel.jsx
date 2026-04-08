import { useState, useEffect } from 'react'

export default function SourcesPanel({ axiosClient }) {
  const [sources, setSources] = useState([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(null)
  const [syncResult, setSyncResult] = useState(null)
  const [selectedFeed, setSelectedFeed] = useState("")

  useEffect(() => {
    fetchSources()
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
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-semibold">Threat Feed Sources</h2>
          <p className="text-sm text-slate-500 mt-1">
            {sources.length} active source{sources.length !== 1 ? 's' : ''} with indicators
          </p>
        </div>
        <button
          onClick={fetchSources}
          className="text-xs text-accent hover:underline"
        >
          Refresh
        </button>
      </div>

      {/* Sync Dropdown */}
      <div className="flex items-center gap-2 mb-4">
        <select
          value={selectedFeed}
          onChange={(e) => setSelectedFeed(e.target.value)}
          className="input py-2 text-sm"
        >
          <option value="">Select feed to sync...</option>
          {FEEDS.map((feed) => (
            <option key={feed.name} value={feed.name}>
              {feed.icon} {feed.label}
            </option>
          ))}
        </select>
        <button
          onClick={handleSync}
          disabled={!selectedFeed || syncing}
          className="btn btn-primary text-sm py-2"
        >
          {syncing ? 'Syncing...' : 'Sync Now'}
        </button>
      </div>

      {/* Active Sources */}
      <div className="flex flex-wrap gap-2 mb-4">
        {loading ? (
          <span className="text-sm text-slate-400">Loading...</span>
        ) : sources.length === 0 ? (
          <span className="text-sm text-slate-400">No active sources yet. Trigger a feed sync.</span>
        ) : (
          sources.map((src) => (
            <span
              key={src}
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-medium bg-green-100 text-green-700"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
              {src}
            </span>
          ))
        )}
      </div>

      {/* All Available Feeds */}
      <div className="border-t border-slate-100 pt-4">
        <h3 className="text-sm font-semibold text-slate-600 mb-3">Available Feeds</h3>
        <div className="grid gap-2 sm:grid-cols-2">
          {FEEDS.map((feed) => {
            const isActive = sources.includes(feed.name)
            return (
              <div
                key={feed.name}
                className={`flex items-center justify-between p-3 rounded-xl border text-sm ${
                  isActive
                    ? 'border-green-200 bg-green-50'
                    : 'border-slate-200 bg-white'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span>{feed.icon}</span>
                  <div>
                    <span className="font-medium">{feed.label}</span>
                    <span
                      className={`ml-2 text-xs px-1.5 py-0.5 rounded ${
                        feed.type === 'free'
                          ? 'bg-blue-100 text-blue-600'
                          : feed.type === 'api-key'
                          ? 'bg-amber-100 text-amber-600'
                          : 'bg-purple-100 text-purple-600'
                      }`}
                    >
                      {feed.type === 'free' ? 'Free' : feed.type === 'api-key' ? 'API Key' : 'Config'}
                    </span>
                  </div>
                </div>
                {isActive ? (
                  <span className="text-xs text-green-600 font-medium">Active</span>
                ) : (
                  <span className="text-xs text-slate-400">—</span>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Sync Result */}
      {syncResult && (
        <div
          className={`mt-4 p-3 rounded-xl text-sm ${
            syncResult.status === 'error'
              ? 'bg-red-50 text-red-700'
              : 'bg-blue-50 text-blue-700'
          }`}
        >
          <code className="text-xs">{syncResult.message}</code>
        </div>
      )}

      {/* CLI Reference */}
      <div className="border-t border-slate-100 pt-4 mt-4">
        <h3 className="text-sm font-semibold text-slate-600 mb-2">Sync Commands</h3>
        <div className="bg-slate-900 text-green-400 rounded-xl p-4 text-xs font-mono space-y-1">
          <div># Sync all feeds at once</div>
          <div>docker compose exec worker celery -A app.celery_app call worker.sync.all</div>
          <div className="h-2"></div>
          <div># Sync individual feeds</div>
          <div>docker compose exec worker celery -A app.celery_app call worker.ingest.urlhaus</div>
          <div>docker compose exec worker celery -A app.celery_app call worker.ingest.feodo</div>
          <div>docker compose exec worker celery -A app.celery_app call worker.ingest.emerging_threats</div>
          <div>docker compose exec worker celery -A app.celery_app call worker.ingest.threatfox</div>
        </div>
      </div>
    </div>
  )
}
