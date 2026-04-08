import { useState } from 'react'

export default function ExportPanel({ axiosClient, selectedIndicators = [], onClearSelection }) {
  const [exporting, setExporting] = useState(null)
  const [bulkAction, setBulkAction] = useState('')
  const [bulkTag, setBulkTag] = useState('')
  const [bulkResult, setBulkResult] = useState(null)

  async function handleExport(format) {
    setExporting(format)
    try {
      if (format === 'stix') {
        const res = await axiosClient.get('/stix/export', { params: { limit: 500 } })
        download(JSON.stringify(res.data, null, 2), 'neeve-stix-bundle.json', 'application/json')
      } else if (format === 'csv') {
        const res = await axiosClient.get('/export/csv', { params: { limit: 5000 }, responseType: 'blob' })
        download(res.data, 'neeve-indicators.csv', 'text/csv')
      } else if (format === 'xlsx') {
        const res = await axiosClient.get('/export/xlsx', { params: { limit: 5000 }, responseType: 'blob' })
        download(res.data, 'neeve-indicators.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
      } else if (format === 'pdf') {
        const res = await axiosClient.get('/export/pdf', { params: { limit: 500 }, responseType: 'blob' })
        download(res.data, 'neeve-threat-report.pdf', 'application/pdf')
      } else if (format === 'json') {
        const res = await axiosClient.get('/export/json', { params: { limit: 5000 } })
        download(JSON.stringify(res.data, null, 2), 'neeve-indicators.json', 'application/json')
      } else if (format === 'ioc-list') {
        const res = await axiosClient.get('/export/ioc-list', { params: { format: 'plain', min_score: 40 } })
        download(res.data, 'iocs.txt', 'text/plain')
      }
    } catch (err) { console.error(err) }
    setExporting(null)
  }

  function download(data, filename, type) {
    // If data is already a blob (from axios blob response), use it directly
    const blob = data instanceof Blob ? data : new Blob([data], { type })
    const url = window.URL.createObjectURL(blob)
    
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.style.display = 'none'
    link.setAttribute('download', filename) // Double up for older browsers
    
    document.body.appendChild(link)
    link.click()
    
    // 3s delay for Mac systems to finish handshake
    setTimeout(() => {
      if (document.body.contains(link)) {
        document.body.removeChild(link)
      }
      window.URL.revokeObjectURL(url)
    }, 3000)
  }

  async function handleBulk() {
    if (!selectedIndicators.length) return
    setExporting('bulk')
    try {
      if (bulkAction === 'tag' && bulkTag) {
        const res = await axiosClient.post('/bulk/tag', { indicator_ids: selectedIndicators, tags: [bulkTag] })
        setBulkResult({ action: 'tagged', count: res.data.updated })
      } else if (bulkAction === 'block') {
        const res = await axiosClient.post('/bulk/block', { indicator_ids: selectedIndicators })
        setBulkResult({ action: 'blocked', count: res.data.blocked })
      }
      onClearSelection?.()
    } catch (err) { console.error(err) }
    setExporting(null)
    setTimeout(() => setBulkResult(null), 5000)
  }

  const formats = [
    { id: 'stix', label: 'STIX 2.1', desc: 'Industry standard. Import to OpenCTI, MISP, Sentinel.', bg: 'bg-purple-100', text: 'text-purple-600' },
    { id: 'csv', label: 'CSV', desc: 'Spreadsheet format. Open in Excel, Google Sheets.', bg: 'bg-emerald-100', text: 'text-emerald-600' },
    { id: 'json', label: 'JSON', desc: 'Full data export for API integration.', bg: 'bg-blue-100', text: 'text-blue-600' },
    { id: 'ioc-list', label: 'IOC List', desc: 'Plain text for firewall rules, DNS sinkhole.', bg: 'bg-amber-100', text: 'text-amber-600' },
  ]

  return (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-base font-semibold text-slate-800 mb-1">Export Intelligence</h3>
        <p className="text-xs text-slate-400 mb-4">Download indicators in various formats</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {formats.map((f) => (
            <button key={f.id} onClick={() => handleExport(f.id)} disabled={exporting}
              className="p-4 rounded-xl border border-slate-200 hover:border-slate-300 hover:shadow-sm transition-all text-left">
              <div className="flex items-center gap-2 mb-2">
                <div className={`w-8 h-8 rounded-lg ${f.bg} flex items-center justify-center ${f.text} font-bold text-xs`}>{f.label[0]}</div>
                <span className="text-sm font-semibold">{f.label}</span>
              </div>
              <p className="text-[11px] text-slate-400">{f.desc}</p>
            </button>
          ))}
        </div>
        {exporting && <div className="mt-4 flex items-center gap-2 text-sm text-accent">
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
          Generating export...
        </div>}
      </div>

      <div className="card">
        <h3 className="text-base font-semibold text-slate-800 mb-1">Bulk Operations</h3>
        <p className="text-xs text-slate-400 mb-4">
          {selectedIndicators.length > 0 ? `${selectedIndicators.length} indicators selected` : 'Select indicators from the table'}
        </p>
        <div className="flex flex-wrap gap-3">
          <select value={bulkAction} onChange={e => setBulkAction(e.target.value)} className="input w-auto py-2" disabled={!selectedIndicators.length}>
            <option value="">Select action...</option>
            <option value="tag">Add Tags</option>
            <option value="block">Block in Firewall</option>
          </select>
          {bulkAction === 'tag' && <input type="text" value={bulkTag} onChange={e => setBulkTag(e.target.value)} placeholder="Enter tag..." className="input w-40 py-2" />}
          <button onClick={handleBulk} disabled={!selectedIndicators.length || !bulkAction || exporting} className="btn btn-primary">{exporting ? 'Processing...' : 'Execute'}</button>
          {selectedIndicators.length > 0 && <button onClick={onClearSelection} className="btn btn-ghost text-sm">Clear</button>}
        </div>
        {bulkResult && <div className="mt-3 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-sm text-emerald-700">✅ {bulkResult.action} {bulkResult.count} indicators</div>}
      </div>

      <div className="card">
        <h3 className="text-base font-semibold text-slate-800 mb-1">Firewall Cron Job</h3>
        <p className="text-xs text-slate-400 mb-4">Add to crontab for automatic blocklist updates</p>
        <pre className="code-block">{`# Every hour:
curl -s "http://localhost:8000/api/v1/blocklist/ips?format=iptables&min_score=50" > /etc/blocklist.rules
iptables-restore < /etc/blocklist.rules

# DNS sinkhole:
curl -s "http://localhost:8000/api/v1/blocklist/domains?format=hosts" >> /etc/hosts`}</pre>
      </div>
    </div>
  )
}
