import { useEffect, useState } from 'react'

export default function DeduplicationSettings({ axiosClient }) {
  const [settings, setSettings] = useState({
    merge_strategy: 'highest_score',
    confidence_weights: {},
    dedup_enabled: true,
    conflict_threshold: 10,
  })
  const [feeds, setFeeds] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [showSuccess, setShowSuccess] = useState(false)

  useEffect(() => {
    fetchData()
  }, [])

  async function fetchData() {
    try {
      const [settingsRes, feedsRes] = await Promise.all([
        axiosClient.get('/indicators/dedup-config'),
        axiosClient.get('/sources'),
      ])
      setSettings(settingsRes.data)
      setFeeds(feedsRes.data || [])
    } catch (err) {
      console.error('Failed to fetch dedup config', err)
    } finally {
      setLoading(false)
    }
  }

  async function saveSettings() {
    setSaving(true)
    try {
      await axiosClient.post('/indicators/dedup-config', settings)
      setShowSuccess(true)
      setTimeout(() => setShowSuccess(false), 2000)
    } catch (err) {
      console.error('Failed to save dedup config', err)
    } finally {
      setSaving(false)
    }
  }

  function updateWeight(feedId, weight) {
    setSettings(prev => ({
      ...prev,
      confidence_weights: { ...prev.confidence_weights, [feedId]: parseInt(weight) }
    }))
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-base font-bold text-slate-900">Deduplication Strategy</h3>
            <p className="text-xs text-slate-500 mt-1">Configure how conflicting IOCs are merged</p>
          </div>
          <label className="flex items-center gap-3 cursor-pointer">
            <span className="text-xs font-bold text-slate-500 uppercase">Enabled</span>
            <div className={`relative w-12 h-6 rounded-full transition-colors ${settings.dedup_enabled ? 'bg-sky-500' : 'bg-slate-200'}`}
              onClick={() => setSettings(prev => ({ ...prev, dedup_enabled: !prev.dedup_enabled }))}>
              <div className={`absolute top-1 w-4 h-4 bg-white rounded-full shadow transition-transform ${settings.dedup_enabled ? 'left-7' : 'left-1'}`}></div>
            </div>
          </label>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {[
            { value: 'highest_score', label: 'Highest Score', desc: 'Use IOC with highest confidence score' },
            { value: 'most_sources', label: 'Consensus', desc: 'Use IOC seen across most feeds' },
            { value: 'average', label: 'Average', desc: 'Calculate average confidence across feeds' },
            { value: 'weighted', label: 'Weighted Average', desc: 'Use feed-specific confidence weights' },
          ].map((option) => (
            <label key={option.value} className={`flex items-start gap-3 p-4 rounded-xl border cursor-pointer transition-all ${
              settings.merge_strategy === option.value ? 'border-sky-500 bg-sky-50' : 'border-slate-200 hover:border-slate-300'
            }`}>
              <input type="radio" name="merge_strategy" value={option.value} checked={settings.merge_strategy === option.value}
                onChange={(e) => setSettings(prev => ({ ...prev, merge_strategy: e.target.value }))}
                className="mt-1 w-4 h-4 text-sky-600" />
              <div>
                <div className="text-sm font-bold text-slate-800">{option.label}</div>
                <div className="text-xs text-slate-500">{option.desc}</div>
              </div>
            </label>
          ))}
        </div>

        <div className="mt-6 pt-6 border-t border-slate-100">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-sm font-bold text-slate-800">Conflict Threshold</div>
              <div className="text-xs text-slate-500">Score difference required to flag as conflict</div>
            </div>
            <div className="flex items-center gap-2">
              <input type="range" min="0" max="50" value={settings.conflict_threshold}
                onChange={(e) => setSettings(prev => ({ ...prev, conflict_threshold: parseInt(e.target.value) }))}
                className="w-24 accent-sky-500" />
              <span className="text-sm font-bold text-slate-700 w-12">{settings.conflict_threshold}%</span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-base font-bold text-slate-900">Feed Confidence Weights</h3>
            <p className="text-xs text-slate-500 mt-1">Adjust importance of each feed when calculating confidence</p>
          </div>
        </div>

        {feeds.length === 0 ? (
          <div className="text-center py-10 text-slate-400">
            <span className="material-symbols-outlined text-3xl mb-2">rss_feed</span>
            <p className="text-xs font-bold">No feeds configured</p>
          </div>
        ) : (
          <div className="space-y-4">
            {feeds.map((feed) => {
              const weight = settings.confidence_weights[feed.name] ?? 100
              return (
                <div key={feed.name} className="flex items-center gap-4 p-4 rounded-xl border border-slate-200">
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center text-white font-bold">
                    {feed.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-bold text-slate-800">{feed.name}</div>
                    <div className="text-xs text-slate-500">Current weight: {weight}%</div>
                  </div>
                  <div className="flex items-center gap-2 w-40">
                    <input type="range" min="0" max="200" value={weight}
                      onChange={(e) => updateWeight(feed.name, e.target.value)}
                      className="flex-1 accent-slate-600" />
                    <span className="text-xs font-bold text-slate-600 w-8">{weight}</span>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
        <div className="mb-4">
          <h3 className="text-base font-bold text-slate-900">Merge Rules Preview</h3>
          <p className="text-xs text-slate-500 mt-1">How conflicting IOCs will be resolved</p>
        </div>
        <div className="bg-slate-50 rounded-xl p-4 font-mono text-xs text-slate-600 space-y-2">
          <div><span className="text-sky-600">IF</span> same IOC from multiple feeds</div>
          <div><span className="text-sky-600">AND</span> score difference {'>'} {settings.conflict_threshold}%</div>
          <div><span className="text-sky-600">THEN</span> flag as conflict for manual review</div>
          <div><span className="text-sky-600">ELSE</span> auto-merge using {settings.merge_strategy === 'weighted' ? 'weighted average' : settings.merge_strategy}</div>
        </div>
      </div>

      <div className="flex justify-end">
        <button onClick={saveSettings} disabled={saving}
          className="px-6 py-3 rounded-xl text-sm font-bold bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 transition-all">
          {saving ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>

      {showSuccess && (
        <div className="fixed bottom-6 right-6 z-50 animate-fade-in">
          <div className="px-4 py-3 rounded-xl shadow-lg bg-emerald-50 border border-emerald-100 flex items-center gap-3">
            <span className="material-symbols-outlined text-emerald-600">check_circle</span>
            <span className="text-sm font-bold text-emerald-600">Configuration saved</span>
          </div>
        </div>
      )}
    </div>
  )
}