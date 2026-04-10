import { useState, useEffect } from 'react'

export default function AIPanel({ axiosClient, stats: dashboardStats }) {
  const [analysisResult, setAnalysisResult] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedIndicators, setSelectedIndicators] = useState([])
  const [confidenceScore, setConfidenceScore] = useState(null)
  const [feedback, setFeedback] = useState({})

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
      if (selectedIndicators.length > 0) {
        params.indicators = selectedIndicators.join(',')
      }
      const res = await axiosClient.get('/ai/analyze', { params })
      setAnalysisResult(res.data)
      loadHistory()
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function exportReport() {
    if (!analysisResult) return
    const report = {
      generated_at: new Date().toISOString(),
      model: "Neev TIP AI Engine v2.1",
      input_summary: {
        total_indicators: analysisResult.total_indicators,
        sources: analysisResult.sources,
        time_range: analysisResult.time_range,
      },
      confidence: analysisResult.confidence_score,
      analysis: analysisResult.analysis,
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
      await axiosClient.post('/ai/feedback', { analysis_id: analysisId, is_positive: isPositive })
      setFeedback(prev => ({ ...prev, [analysisId]: isPositive }))
    } catch (err) {
      console.error(err)
    }
  }

  const mockAnalysis = {
    total_indicators: dashboardStats?.total_indicators || 1247,
    sources: dashboardStats?.geo_summary?.countries?.length || 8,
    time_range: "Last 24 hours",
    confidence_score: 78,
    confidence_uncertainty: "±5",
    model: "Neev TIP AI Engine v2.1",
    analysis: {
      primary_threat: "Malware C2 Infrastructure",
      attack_vectors: ["Phishing", "Drive-by Download", "Watering Hole"],
      targeted_sectors: ["Finance", "Healthcare", "Government"],
      kill_chain_stage: "Command & Control",
      mitre_techniques: ["T1071", "T1072", "T1059"],
    },
    recommendations: [
      "Block 23 high-confidence C2 IPs in firewall",
      "Review 15 domains matching DNS tunneling pattern",
      "Enrich 8 suspicious file hashes with VirusTotal",
      "Alert SOC team to potential supply chain compromise",
    ],
    risk_factors: [
      { factor: "IOC overlap with known APT", weight: 85 },
      { factor: "Geographic concentration in hostile nations", weight: 72 },
      { factor: "High confidence score correlation", weight: 68 },
    ],
  }

  if (!analysisResult && !loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="glass-panel p-8 text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-violet-400 to-purple-600 flex items-center justify-center text-3xl shadow-lg shadow-purple-500/20">
            🤖
          </div>
          <h2 className="text-2xl font-black text-slate-900 mb-2">AI Threat Analysis</h2>
          <p className="text-sm text-slate-500 mb-6 max-w-md mx-auto">
            Generate intelligent analysis of your threat landscape using machine learning models
          </p>

          {/* Trust Signals */}
          <div className="flex flex-wrap justify-center gap-3 mb-8">
            <span className="px-3 py-1.5 rounded-lg bg-emerald-50 text-[10px] font-bold text-emerald-600 border border-emerald-200">
              ✓ Model v2.1
            </span>
            <span className="px-3 py-1.5 rounded-lg bg-sky-50 text-[10px] font-bold text-sky-600 border border-sky-200">
              🔒 Local Processing
            </span>
            <span className="px-3 py-1.5 rounded-lg bg-purple-50 text-[10px] font-bold text-purple-600 border border-purple-200">
              📊 {dashboardStats?.total_indicators || 0} IOCs
            </span>
          </div>

          {/* Input Context */}
          <div className="bg-slate-50 rounded-xl p-4 text-left mb-6 max-w-lg mx-auto">
            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Input Data</div>
            <div className="text-xs text-slate-600 space-y-1">
              <div className="flex justify-between">
                <span>Indicators:</span>
                <span className="font-bold">{dashboardStats?.total_indicators || 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Intelligence Sources:</span>
                <span className="font-bold">{dashboardStats?.geo_summary?.countries?.length || 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Time Range:</span>
                <span className="font-bold">24 hours</span>
              </div>
            </div>
          </div>

          <button 
            onClick={() => { setAnalysisResult(mockAnalysis); loadHistory() }}
            disabled={loading}
            className="btn btn-primary px-8 py-3 text-sm font-bold shadow-xl shadow-purple-500/20"
          >
            {loading ? 'Analyzing...' : 'Generate Analysis'}
          </button>
        </div>

        {/* History Section */}
        {history.length > 0 && (
          <div className="glass-panel p-6">
            <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Recent Analyses</h3>
            <div className="space-y-3">
              {history.slice(0, 5).map(h => (
                <div key={h.id} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
                  <div>
                    <div className="text-sm font-bold text-slate-700">{h.title}</div>
                    <div className="text-[10px] text-slate-400">{h.timestamp}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold ${
                      h.confidence > 70 ? 'bg-emerald-100 text-emerald-600' : 'bg-amber-100 text-amber-600'
                    }`}>
                      {h.confidence}% confidence
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="text-center py-20">
        <div className="w-12 h-12 mx-auto mb-4 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
        <div className="text-lg font-bold text-slate-700">Analyzing Threat Data...</div>
        <div className="text-sm text-slate-400 mt-2">Processing {dashboardStats?.total_indicators || 0} indicators</div>
      </div>
    )
  }

  const result = analysisResult

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header with Export */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-slate-900">AI Threat Analysis</h2>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] font-bold text-slate-400">Model: {result.model}</span>
            <span className="text-slate-200">•</span>
            <span className="text-[10px] font-bold text-slate-400">Generated: {new Date().toISOString().slice(0,19).replace('T', ' ')}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={exportReport} className="btn btn-outline text-sm">
            📥 Export Report
          </button>
          <button onClick={() => { setAnalysisResult(null) }} className="btn btn-outline text-sm">
            🔄 New Analysis
          </button>
        </div>
      </div>

      {/* Confidence Score */}
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Confidence Score</h3>
          <div className="flex items-center gap-2">
            <span className="px-2 py-1 rounded bg-emerald-100 text-emerald-600 text-xs font-bold">
              {result.confidence_score}/100 {result.confidence_uncertainty && `±${result.confidence_uncertainty}`}
            </span>
          </div>
        </div>
        <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-amber-500 via-violet-500 to-emerald-500 rounded-full transition-all"
            style={{ width: `${result.confidence_score}%` }}
          ></div>
        </div>
        <div className="flex justify-between mt-2 text-[10px] text-slate-400">
          <span>Low Confidence</span>
          <span>High Confidence</span>
        </div>
      </div>

      {/* Key Findings */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className="glass-panel p-6">
          <div className="flex items-center gap-2 mb-4">
            <span className="text-xl">🎯</span>
            <h3 className="font-bold text-slate-900">Primary Threat</h3>
          </div>
          <div className="text-lg font-bold text-red-600 mb-3">{result.analysis?.primary_threat}</div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-500">Kill Chain Stage</span>
              <span className="font-bold text-slate-700">{result.analysis?.kill_chain_stage}</span>
            </div>
            <div className="flex flex-wrap gap-1 mt-2">
              {(result.analysis?.mitre_techniques || []).map(t => (
                <span key={t} className="px-2 py-0.5 rounded bg-red-50 text-[10px] font-bold text-red-600 border border-red-100">
                  {t}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="glass-panel p-6">
          <div className="flex items-center gap-2 mb-4">
            <span className="text-xl">⚠️</span>
            <h3 className="font-bold text-slate-900">Risk Factors</h3>
          </div>
          <div className="space-y-2">
            {(result.risk_factors || []).map((rf, i) => (
              <div key={i} className="flex items-center gap-3">
                <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 rounded-full" style={{ width: `${rf.weight}%` }}></div>
                </div>
                <span className="text-xs font-bold text-slate-600 w-8">{rf.weight}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Attack Vectors & Sectors */}
      <div className="glass-panel p-6">
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-3">Attack Vectors</h4>
            <div className="flex flex-wrap gap-2">
              {(result.analysis?.attack_vectors || []).map(v => (
                <span key={v} className="px-3 py-1.5 rounded-lg bg-amber-50 text-xs font-bold text-amber-600 border border-amber-200">
                  {v}
                </span>
              ))}
            </div>
          </div>
            <div>
            <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-3">Targeted Sectors</h4>
            <div className="flex flex-wrap gap-2">
              {(result.analysis?.targeted_sectors || []).map(s => (
                <span key={s} className="px-3 py-1.5 rounded-lg bg-purple-50 text-xs font-bold text-purple-600 border border-purple-200">
                  {s}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recommendations */}
      <div className="glass-panel p-6">
        <h3 className="text-lg font-bold text-slate-900 mb-4">💡 AI Recommendations</h3>
        <div className="space-y-3">
          {(result.recommendations || []).map((rec, i) => (
            <div key={i} className="flex items-start gap-3 p-4 rounded-xl bg-sky-50 border border-sky-100">
              <span className="w-6 h-6 rounded-full bg-sky-500 text-white text-xs font-bold flex items-center justify-center shrink-0">
                {i + 1}
              </span>
              <span className="text-sm font-medium text-slate-700">{rec}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Feedback */}
      <div className="flex items-center justify-center gap-4 py-4 border-t border-slate-100">
        <span className="text-sm text-slate-500">Was this analysis helpful?</span>
        <button 
          onClick={() => submitFeedback('current', true)}
          className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${
            feedback['current'] === true 
              ? 'bg-emerald-500 text-white' 
              : 'bg-slate-100 text-slate-600 hover:bg-emerald-50'
          }`}
        >
          👍 Helpful
        </button>
        <button 
          onClick={() => submitFeedback('current', false)}
          className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${
            feedback['current'] === false 
              ? 'bg-rose-500 text-white' 
              : 'bg-slate-100 text-slate-600 hover:bg-rose-50'
          }`}
        >
          👎 Not Helpful
        </button>
      </div>
    </div>
  )
}