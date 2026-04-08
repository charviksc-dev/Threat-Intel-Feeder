import { useState, useEffect } from 'react'

const TACTICS_ORDER = [
  'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
  'collection', 'command-and-control', 'exfiltration', 'impact',
]

const TACTIC_LABELS = {
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Priv Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Cred Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Move',
  'collection': 'Collection',
  'command-and-control': 'C2',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
}

export default function AttackCoverage({ axiosClient }) {
  const [coverage, setCoverage] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selectedTactic, setSelectedTactic] = useState(null)

  useEffect(() => { loadCoverage() }, [])

  async function loadCoverage() {
    setLoading(true)
    try {
      const res = await axiosClient.get('/attack/coverage')
      setCoverage(res.data)
    } catch (err) { console.error(err) }
    setLoading(false)
  }

  if (loading) {
    return (
      <div className="card text-center py-12">
        <div className="inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mb-3"></div>
        <div className="text-sm text-slate-500">Loading ATT&CK coverage...</div>
      </div>
    )
  }

  const byTactic = coverage?.by_tactic || {}
  const techniques = coverage?.techniques || []

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="text-2xl font-bold text-primary">{coverage?.total_techniques_covered || 0}</div>
          <div className="text-xs text-slate-500">Techniques Covered</div>
        </div>
        <div className="card">
          <div className="text-2xl font-bold text-accent">{Object.keys(byTactic).length}</div>
          <div className="text-xs text-slate-500">Tactics Active</div>
        </div>
        <div className="card">
          <div className="text-2xl font-bold text-purple-600">{techniques.reduce((s, t) => s + (t.indicator_count || 0), 0)}</div>
          <div className="text-xs text-slate-500">Mapped IOCs</div>
        </div>
        <div className="card">
          <div className="text-2xl font-bold text-emerald-600">{Math.round((Object.keys(byTactic).length / 12) * 100)}%</div>
          <div className="text-xs text-slate-500">Kill Chain Coverage</div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-800">MITRE ATT&CK Kill Chain</h3>
            <p className="text-xs text-slate-400 mt-0.5">Click a tactic to see techniques</p>
          </div>
          <button onClick={loadCoverage} className="btn btn-ghost text-xs">Refresh</button>
        </div>
        <div className="overflow-x-auto pb-2">
          <div className="flex gap-1.5 min-w-[900px]">
            {TACTICS_ORDER.map((tactic) => {
              const techs = byTactic[tactic] || []
              const active = techs.length > 0
              const selected = selectedTactic === tactic
              const total = techs.reduce((s, t) => s + (t.indicator_count || 0), 0)
              return (
                <button key={tactic} onClick={() => setSelectedTactic(selected ? null : tactic)}
                  className={`flex-1 min-w-[72px] p-2 rounded-lg text-center transition-all border ${
                    active ? selected ? 'bg-primary text-white border-primary shadow-lg scale-105' : 'bg-primary/10 text-primary border-primary/30 hover:bg-primary/20' : 'bg-slate-50 text-slate-400 border-slate-200'
                  }`}>
                  <div className="text-[10px] font-semibold truncate">{TACTIC_LABELS[tactic]}</div>
                  {active ? (<><div className="text-lg font-bold mt-1">{techs.length}</div><div className="text-[9px] opacity-70">{total} IOCs</div></>) : (<div className="text-lg mt-1 opacity-30">—</div>)}
                </button>
              )
            })}
          </div>
        </div>
      </div>

      {selectedTactic && byTactic[selectedTactic] && (
        <div className="card border-l-4 border-l-primary animate-fade-in">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold">{TACTIC_LABELS[selectedTactic]} Techniques</h3>
            <button onClick={() => setSelectedTactic(null)} className="text-slate-400 hover:text-slate-600">✕</button>
          </div>
          <div className="space-y-3">
            {byTactic[selectedTactic].map((tech) => (
              <div key={tech.technique_id} className="flex items-center justify-between p-3 bg-slate-50 rounded-xl">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-xs font-mono font-bold text-primary">{tech.technique_id}</div>
                  <div>
                    <div className="text-sm font-medium text-slate-800">{tech.technique_name}</div>
                    <div className="text-xs text-slate-400">{tech.threat_types?.join(', ')}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-lg font-bold text-slate-700">{tech.indicator_count}</div>
                  <div className="text-[10px] text-slate-400">IOCs</div>
                </div>
              </div>
            ))}
          </div>
          <a href={`https://attack.mitre.org/tactics/${selectedTactic}/`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 mt-4 text-xs text-accent hover:underline">View on MITRE ATT&CK ↗</a>
        </div>
      )}

      <div className="card">
        <h3 className="text-base font-semibold mb-4">All Mapped Techniques</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead><tr className="table-header">
              <th className="px-4 py-3 rounded-l-lg">ID</th>
              <th className="px-4 py-3">Technique</th>
              <th className="px-4 py-3">Tactic</th>
              <th className="px-4 py-3">Threat Types</th>
              <th className="px-4 py-3 rounded-r-lg">IOCs</th>
            </tr></thead>
            <tbody>
              {techniques.map((tech) => (
                <tr key={tech.technique_id} className="table-row">
                  <td className="px-4 py-3"><a href={`https://attack.mitre.org/techniques/${tech.technique_id}/`} target="_blank" rel="noopener noreferrer" className="font-mono text-xs text-accent hover:underline">{tech.technique_id}</a></td>
                  <td className="px-4 py-3 text-sm font-medium">{tech.technique_name}</td>
                  <td className="px-4 py-3"><span className="badge badge-info">{TACTIC_LABELS[tech.tactic] || tech.tactic}</span></td>
                  <td className="px-4 py-3"><div className="flex flex-wrap gap-1">{tech.threat_types?.map(t => <span key={t} className="badge badge-neutral">{t}</span>)}</div></td>
                  <td className="px-4 py-3 text-sm font-bold">{tech.indicator_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
