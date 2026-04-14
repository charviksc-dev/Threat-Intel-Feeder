import { useState, useEffect } from 'react'

export default function AIPanel({ axiosClient, stats: dashboardStats }) {
  const [activeTab, setActiveTab] = useState('analyze')
  const [analysisResult, setAnalysisResult] = useState(null)
  const [patterns, setPatterns] = useState(null)
  const [anomalies, setAnomalies] = useState(null)
  const [attackChain, setAttackChain] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedIndicators, setSelectedIndicators] = useState('')
  const [feedback, setFeedback] = useState({})
  const [indicatorInput, setIndicatorInput] = useState('')
  const [hoursWindow, setHoursWindow] = useState(24)

  useEffect(() => {
    loadHistory()
  }, [])

  async function loadHistory() {
    try {
      const res = await axiosClient.get('/ai/history')
      setHistory(res.data || [])
    } catch (err) {
      console.error(err)
      setHistory([])
    }
  }

  async function loadAnalysis() {
    setLoading(true)
    try {
      const params = {}
      if (selectedIndicators) {
        params.indicators = selectedIndicators
      }
      const res = await axiosClient.get('/ai/analyze', { params })
      setAnalysisResult(res.data)
      loadHistory()
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function loadPatterns() {
    setLoading(true)
    try {
      const res = await axiosClient.get('/ai/patterns')
      setPatterns(res.data)
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function loadAnomalies() {
    setLoading(true)
    try {
      const res = await axiosClient.get('/ai/anomalies', { params: { hours: hoursWindow } })
      setAnomalies(res.data)
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function loadAttackChain() {
    if (!indicatorInput) {
      alert('Please enter an indicator value')
      return
    }
    setLoading(true)
    try {
      const res = await axiosClient.get('/ai/attack-chain', { params: { indicator: indicatorInput } })
      setAttackChain(res.data)
    } catch (err) {
      console.error(err)
      alert('Indicator not found or analysis failed')
    }
    setLoading(false)
  }

  async function exportReport() {
    if (!analysisResult) return
    const report = {
      generated_at: new Date().toISOString(),
      model: analysisResult.model || "Neev TIP Synthetic Intelligence Engine v3.0",
      total_indicators_analyzed: analysisResult.total_indicators_analyzed,
      overall_threat_score: analysisResult.overall_threat_score,
      detected_patterns: analysisResult.detected_patterns,
      detected_anomalies: analysisResult.detected_anomalies,
      attack_chain_analysis: analysisResult.attack_chain_analysis,
      recommendations: analysisResult.recommendations,
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ai-threat-report-${new Date().toISOString().slice(0,10)}.json`
    a.click()
  }

  async function submitFeedback(analysisId, isPositive) {
    try {
      await axiosClient.post('/ai/feedback', { analysis_id: analysisId, is_positive: is_positive })
      setFeedback(prev => ({ ...prev, [analysisId]: isPositive }))
    } catch (err) {
      console.error(err)
    }
  }

  if (loading) {
    return (
      <div className="text-center py-20">
        <div className="w-12 h-12 mx-auto mb-4 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
        <div className="text-lg font-bold text-slate-700">Analyzing Threat Data...</div>
        <div className="text-sm text-slate-400 mt-2">Processing indicators with Synthetic Intelligence Engine</div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-slate-200">
        {[
          { id: 'analyze', label: 'Analysis', icon: '🤖' },
          { id: 'patterns', label: 'Patterns', icon: '🔍' },
          { id: 'anomalies', label: 'Anomalies', icon: '⚠️' },
          { id: 'attack-chain', label: 'Attack Chain', icon: '⛓️' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-sm font-bold transition-all border-b-2 ${
              activeTab === tab.id
                ? 'border-purple-500 text-purple-600'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            <span className="mr-1">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Analysis Tab */}
      {activeTab === 'analyze' && (
        <div className="space-y-6">
          {!analysisResult ? (
            <div className="glass-panel p-8 text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-violet-400 to-purple-600 flex items-center justify-center text-3xl shadow-lg shadow-purple-500/20">
                🤖
              </div>
              <h2 className="text-2xl font-black text-slate-900 mb-2">AI Threat Analysis</h2>
              <p className="text-sm text-slate-500 mb-6 max-w-md mx-auto">
                Generate comprehensive threat analysis using Synthetic Intelligence Engine v3.0
              </p>

              <div className="flex flex-wrap justify-center gap-3 mb-8">
                <span className="px-3 py-1.5 rounded-lg bg-emerald-50 text-[10px] font-bold text-emerald-600 border border-emerald-200">
                  ✓ Model v3.0
                </span>
                <span className="px-3 py-1.5 rounded-lg bg-sky-50 text-[10px] font-bold text-sky-600 border border-sky-200">
                  🔒 Local Processing
                </span>
                <span className="px-3 py-1.5 rounded-lg bg-purple-50 text-[10px] font-bold text-purple-600 border border-purple-200">
                  📊 {dashboardStats?.total_indicators || 0} IOCs
                </span>
              </div>

              <div className="bg-slate-50 rounded-xl p-4 text-left mb-6 max-w-lg mx-auto">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Optional: Specific Indicators</div>
                <input
                  type="text"
                  value={selectedIndicators}
                  onChange={(e) => setSelectedIndicators(e.target.value)}
                  placeholder="Enter comma-separated indicators (optional)"
                  className="w-full px-4 py-2 rounded-lg border border-slate-200 text-sm"
                />
              </div>

              <button 
                onClick={loadAnalysis}
                disabled={loading}
                className="btn btn-primary px-8 py-3 text-sm font-bold shadow-xl shadow-purple-500/20"
              >
                {loading ? 'Analyzing...' : 'Generate Analysis'}
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-black text-slate-900">AI Threat Analysis</h2>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] font-bold text-slate-400">Model: {analysisResult.model}</span>
                    <span className="text-slate-200">•</span>
                    <span className="text-[10px] font-bold text-slate-400">Indicators: {analysisResult.total_indicators_analyzed}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={exportReport} className="btn btn-outline text-sm">
                    📥 Export
                  </button>
                  <button onClick={() => { setAnalysisResult(null) }} className="btn btn-outline text-sm">
                    🔄 New
                  </button>
                </div>
              </div>

              {/* Overall Threat Score */}
              <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Overall Threat Score</h3>
                  <span className="px-3 py-1 rounded-lg bg-gradient-to-r from-amber-500 to-red-500 text-white text-sm font-bold">
                    {analysisResult.overall_threat_score}/100
                  </span>
                </div>
                <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500 rounded-full transition-all"
                    style={{ width: `${analysisResult.overall_threat_score}%` }}
                  ></div>
                </div>
              </div>

              {/* Detected Patterns */}
              {analysisResult.detected_patterns && analysisResult.detected_patterns.length > 0 && (
                <div className="glass-panel p-6">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Detected Patterns</h3>
                  <div className="space-y-3">
                    {analysisResult.detected_patterns.map((pattern, i) => (
                      <div key={i} className="p-4 rounded-xl bg-red-50 border border-red-100">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-bold text-red-600">{pattern.type}</span>
                          <span className={`px-2 py-1 rounded text-[10px] font-bold ${
                            pattern.severity === 'critical' ? 'bg-red-500 text-white' :
                            pattern.severity === 'high' ? 'bg-orange-500 text-white' :
                            'bg-amber-500 text-white'
                          }`}>
                            {pattern.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-600 mb-2">{pattern.description}</p>
                        <div className="flex flex-wrap gap-1">
                          {pattern.mitre_techniques.map(t => (
                            <span key={t} className="px-2 py-0.5 rounded bg-red-100 text-[10px] font-bold text-red-600">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Detected Anomalies */}
              {analysisResult.detected_anomalies && analysisResult.detected_anomalies.length > 0 && (
                <div className="glass-panel p-6">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Detected Anomalies</h3>
                  <div className="space-y-3">
                    {analysisResult.detected_anomalies.map((anomaly, i) => (
                      <div key={i} className="p-4 rounded-xl bg-amber-50 border border-amber-100">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-bold text-amber-600">{anomaly.type}</span>
                          <span className="text-[10px] font-bold text-slate-600">Score: {anomaly.score}</span>
                        </div>
                        <p className="text-xs text-slate-600">{anomaly.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attack Chain Analysis */}
              {analysisResult.attack_chain_analysis && (
                <div className="glass-panel p-6">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Attack Chain Analysis</h3>
                  <div className="space-y-3">
                    <div>
                      <span className="text-xs text-slate-500">Detected Stages:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {analysisResult.attack_chain_analysis.detected_stages.map(s => (
                          <span key={s} className="px-2 py-0.5 rounded bg-purple-100 text-[10px] font-bold text-purple-600">
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">MITRE Techniques:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {analysisResult.attack_chain_analysis.mitre_techniques.map(t => (
                          <span key={t} className="px-2 py-0.5 rounded bg-blue-100 text-[10px] font-bold text-blue-600">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="text-xs text-slate-600">
                      Completion: {analysisResult.attack_chain_analysis.completion_percentage}%
                    </div>
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {analysisResult.recommendations && analysisResult.recommendations.length > 0 && (
                <div className="glass-panel p-6">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">AI Recommendations</h3>
                  <div className="space-y-3">
                    {analysisResult.recommendations.map((rec, i) => (
                      <div key={i} className={`flex items-start gap-3 p-4 rounded-xl border ${
                        rec.priority === 'critical' ? 'bg-red-50 border-red-200' :
                        rec.priority === 'high' ? 'bg-orange-50 border-orange-200' :
                        rec.priority === 'medium' ? 'bg-amber-50 border-amber-200' :
                        'bg-sky-50 border-sky-200'
                      }`}>
                        <span className="w-6 h-6 rounded-full bg-sky-500 text-white text-xs font-bold flex items-center justify-center shrink-0">
                          {i + 1}
                        </span>
                        <div>
                          <div className="text-sm font-bold text-slate-700">{rec.action}</div>
                          <div className="text-xs text-slate-500 mt-1">{rec.details}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Patterns Tab */}
      {activeTab === 'patterns' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-black text-slate-900">Pattern Detection</h2>
            <button onClick={loadPatterns} disabled={loading} className="btn btn-primary text-sm">
              Detect Patterns
            </button>
          </div>

          {!patterns ? (
            <div className="glass-panel p-8 text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-blue-400 to-cyan-600 flex items-center justify-center text-3xl">
                🔍
              </div>
              <h2 className="text-2xl font-black text-slate-900 mb-2">Threat Pattern Detection</h2>
              <p className="text-sm text-slate-500 mb-6">
                Detect known threat patterns in your indicators (C2, phishing, malware families)
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="text-sm text-slate-500">
                Analyzed {patterns.indicators_analyzed} indicators, found {patterns.patterns_detected} patterns
              </div>
              {patterns.patterns.map((pattern, i) => (
                <div key={i} className="glass-panel p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <span className="font-bold text-slate-900">{pattern.type}</span>
                      <span className="ml-2 text-xs text-slate-500">Confidence: {(pattern.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <span className={`px-2 py-1 rounded text-[10px] font-bold ${
                      pattern.severity === 'critical' ? 'bg-red-500 text-white' :
                      pattern.severity === 'high' ? 'bg-orange-500 text-white' :
                      'bg-amber-500 text-white'
                    }`}>
                      {pattern.severity}
                    </span>
                  </div>
                  <p className="text-sm text-slate-600 mb-3">{pattern.description}</p>
                  <div className="flex flex-wrap gap-1 mb-3">
                    {pattern.mitre_techniques.map(t => (
                      <span key={t} className="px-2 py-0.5 rounded bg-blue-100 text-[10px] font-bold text-blue-600">
                        {t}
                      </span>
                    ))}
                  </div>
                  <div className="text-xs text-slate-500">
                    {pattern.indicator_count} indicators matched
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Anomalies Tab */}
      {activeTab === 'anomalies' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-black text-slate-900">Anomaly Detection</h2>
            <div className="flex gap-2 items-center">
              <select
                value={hoursWindow}
                onChange={(e) => setHoursWindow(parseInt(e.target.value))}
                className="px-3 py-2 rounded-lg border border-slate-200 text-sm"
              >
                <option value="6">6 hours</option>
                <option value="24">24 hours</option>
                <option value="48">48 hours</option>
                <option value="72">72 hours</option>
              </select>
              <button onClick={loadAnomalies} disabled={loading} className="btn btn-primary text-sm">
                Detect Anomalies
              </button>
            </div>
          </div>

          {!anomalies ? (
            <div className="glass-panel p-8 text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-amber-400 to-orange-600 flex items-center justify-center text-3xl">
                ⚠️
              </div>
              <h2 className="text-2xl font-black text-slate-900 mb-2">Behavioral Anomaly Detection</h2>
              <p className="text-sm text-slate-500 mb-6">
                Detect unusual patterns in indicator data (ASN concentration, geographic clustering, temporal surges)
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="text-sm text-slate-500">
                Analyzed {anomalies.indicators_analyzed} indicators in {anomalies.time_window_hours}h window, found {anomalies.anomalies_detected} anomalies
              </div>
              {anomalies.anomalies.map((anomaly, i) => (
                <div key={i} className="glass-panel p-6">
                  <div className="flex items-center justify-between mb-4">
                    <span className="font-bold text-slate-900">{anomaly.type}</span>
                    <span className={`px-2 py-1 rounded text-[10px] font-bold ${
                      anomaly.severity === 'high' ? 'bg-red-500 text-white' :
                      anomaly.severity === 'medium' ? 'bg-amber-500 text-white' :
                      'bg-blue-500 text-white'
                    }`}>
                      {anomaly.severity}
                    </span>
                  </div>
                  <p className="text-sm text-slate-600 mb-3">{anomaly.description}</p>
                  <div className="text-xs text-slate-500">
                    Score: {anomaly.score.toFixed(2)} • {anomaly.affected_count} indicators affected
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Attack Chain Tab */}
      {activeTab === 'attack-chain' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-black text-slate-900">Attack Chain Reconstruction</h2>
          </div>

          <div className="glass-panel p-6">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Indicator to Analyze</div>
            <div className="flex gap-2">
              <input
                type="text"
                value={indicatorInput}
                onChange={(e) => setIndicatorInput(e.target.value)}
                placeholder="Enter indicator (IP, domain, hash, URL)"
                className="flex-1 px-4 py-2 rounded-lg border border-slate-200 text-sm"
              />
              <button onClick={loadAttackChain} disabled={loading} className="btn btn-primary text-sm">
                Analyze
              </button>
            </div>
          </div>

          {!attackChain ? (
            <div className="glass-panel p-8 text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-purple-400 to-pink-600 flex items-center justify-center text-3xl">
                ⛓️
              </div>
              <h2 className="text-2xl font-black text-slate-900 mb-2">MITRE ATT&CK Attack Chain</h2>
              <p className="text-sm text-slate-500 mb-6">
                Reconstruct attack chains and map to MITRE ATT&CK framework
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-4">
                  <span className="font-bold text-slate-900">{attackChain.indicator}</span>
                  <span className="px-3 py-1 rounded-lg bg-gradient-to-r from-amber-500 to-red-500 text-white text-sm font-bold">
                    Score: {attackChain.threat_score}
                  </span>
                </div>
              </div>

              <div className="glass-panel p-6">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Attack Chain Stages</h3>
                <div className="flex flex-wrap gap-2">
                  {attackChain.attack_chain.detected_stages.map(s => (
                    <span key={s} className="px-3 py-1.5 rounded-lg bg-purple-50 text-xs font-bold text-purple-600 border border-purple-200">
                      {s}
                    </span>
                  ))}
                </div>
              </div>

              <div className="glass-panel p-6">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">MITRE Techniques</h3>
                <div className="flex flex-wrap gap-2">
                  {attackChain.attack_chain.mitre_techniques.map(t => (
                    <span key={t} className="px-3 py-1.5 rounded-lg bg-blue-50 text-xs font-bold text-blue-600 border border-blue-200">
                      {t}
                    </span>
                  ))}
                </div>
              </div>

              <div className="glass-panel p-6">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Attack Chain Completion</h3>
                <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full"
                    style={{ width: `${attackChain.attack_chain.completion_percentage}%` }}
                  ></div>
                </div>
                <div className="text-center text-xs text-slate-500 mt-2">
                  {attackChain.attack_chain.completion_percentage}% complete
                </div>
              </div>

              <div className="glass-panel p-6">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Likely Threat Actors</h3>
                <div className="flex flex-wrap gap-2">
                  {attackChain.attack_chain.likely_attackers.map(actor => (
                    <span key={actor} className="px-3 py-1.5 rounded-lg bg-red-50 text-xs font-bold text-red-600 border border-red-200">
                      {actor}
                    </span>
                  ))}
                </div>
              </div>

              <div className="glass-panel p-6">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Next Predicted Stages</h3>
                <div className="flex flex-wrap gap-2">
                  {attackChain.attack_chain.next_predicted_stages.map(stage => (
                    <span key={stage} className="px-3 py-1.5 rounded-lg bg-amber-50 text-xs font-bold text-amber-600 border border-amber-200">
                      {stage}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* History Section */}
      {history.length > 0 && (
        <div className="glass-panel p-6">
          <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Recent Analyses</h3>
          <div className="space-y-3">
            {history.slice(0, 5).map(h => (
              <div key={h.id} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
                <div>
                  <div className="text-sm font-bold text-slate-700">Analysis #{h.id.split('-')[1]}</div>
                  <div className="text-[10px] text-slate-400">{h.timestamp}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-500">{h.total_indicators_analyzed || h.total_indicators} IOCs</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}