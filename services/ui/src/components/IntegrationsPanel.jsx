import { useState } from 'react'

const INTEGRATIONS = [
  {
    id: 'wazuh',
    name: 'Wazuh SIEM',
    icon: '🛡️',
    description: 'Receive alerts from Wazuh agents via Active Response webhook',
    category: 'siem',
    setupSteps: [
      'Add this webhook URL to your Wazuh manager ossec.conf:',
      '<integration>',
      '  <name>custom-neev</name>',
      '  <hook_url>http://YOUR_HOST:8000/api/v1/integrations/wazuh/webhook</hook_url>',
      '  <alert_format>json</alert_format>',
      '</integration>',
      'Restart Wazuh manager: systemctl restart wazuh-manager',
    ],
    endpoint: '/api/v1/integrations/wazuh/webhook',
    method: 'POST',
    statusKey: 'wazuh',
  },
  {
    id: 'suricata',
    name: 'Suricata IDS/IPS',
    icon: '🔍',
    description: 'Ingest Suricata EVE JSON logs for alert, DNS, TLS, and HTTP IOCs',
    category: 'ids',
    setupSteps: [
      'Enable EVE output in suricata.yaml:',
      'outputs:',
      '  - eve-log:',
      '      enabled: yes',
      '      types: [alert, dns, tls, http, fileinfo]',
      'Ship logs using Filebeat, Vector, or a cron curl:',
      'curl -X POST http://YOUR_HOST:8000/api/v1/integrations/suricata/eve \\',
      '  -H "Content-Type: application/json" -d @eve_event.json',
    ],
    endpoint: '/api/v1/integrations/suricata/eve',
    method: 'POST',
    statusKey: 'suricata',
  },
  {
    id: 'zeek',
    name: 'Zeek NSM',
    icon: '🌐',
    description: 'Ingest Zeek logs (conn, dns, http, ssl, files, notice, x509)',
    category: 'ids',
    setupSteps: [
      'Enable JSON logging in Zeek:',
      '@load policy/tuning/json-logs.zeek',
      'Ship logs per type:',
      'curl -X POST http://YOUR_HOST:8000/api/v1/integrations/zeek/dns -d @dns.json',
      'curl -X POST http://YOUR_HOST:8000/api/v1/integrations/zeek/http -d @http.json',
      'curl -X POST http://YOUR_HOST:8000/api/v1/integrations/zeek/conn -d @conn.json',
      'curl -X POST http://YOUR_HOST:8000/api/v1/integrations/zeek/ssl -d @ssl.json',
      'curl -X POST http://YOUR_HOST:8000/api/v1/integrations/zeek/notice -d @notice.json',
    ],
    endpoint: '/api/v1/integrations/zeek/{log_type}',
    method: 'POST',
    statusKey: 'zeek',
  },
  {
    id: 'misp',
    name: 'MISP',
    icon: '🔄',
    description: 'Bidirectional sync - pull IOCs from MISP and push high-confidence IOCs back',
    category: 'threat-intel',
    setupSteps: [
      'Get your MISP API key from MISP > Administration > Auth Keys',
      'Set MISP_API_URL and MISP_API_KEY in .env',
      'Pull IOCs: GET /api/v1/integrations/misp/pull?days=7',
      'Push IOCs: POST /api/v1/integrations/misp/push?min_score=50',
    ],
    endpoint: '/api/v1/integrations/misp/pull',
    method: 'GET',
    statusKey: 'misp',
  },
  {
    id: 'thehive',
    name: 'TheHive',
    icon: '📋',
    description: 'Push correlated alerts and IOCs to TheHive for case management',
    category: 'soar',
    setupSteps: [
      'Get API key from TheHive > Administration > API Keys',
      'Set THEHIVE_URL and THEHIVE_API_KEY in .env',
      'High-severity Wazuh alerts auto-push to TheHive',
      'Manual push: POST /api/v1/integrations/thehive/push',
    ],
    endpoint: '/api/v1/integrations/thehive/push',
    method: 'POST',
    statusKey: 'thehive',
  },
  {
    id: 'cortex',
    name: 'Cortex',
    icon: '🧠',
    description: 'Use Cortex analyzers for deep IOC enrichment',
    category: 'soar',
    setupSteps: [
      'Get API key from Cortex > Organization > API Keys',
      'Set CORTEX_URL and CORTEX_API_KEY in .env',
      'Cortex analyzers run automatically via TheHive integration',
    ],
    endpoint: '',
    method: '',
    statusKey: 'cortex',
  },
  {
    id: 'firewall-export',
    name: 'Firewall Export',
    icon: '🔥',
    description: 'Export IP/domain blocklists for iptables, pf, nftables, or DNS sinkhole',
    category: 'firewall',
    setupSteps: [
      'Add to your firewall cron job:',
      'curl -s http://YOUR_HOST:8000/api/v1/blocklist/ips?format=iptables > /etc/blocklist.rules',
      'iptables-restore < /etc/blocklist.rules',
      '',
      'For DNS sinkhole:',
      'curl -s http://YOUR_HOST:8000/api/v1/blocklist/domains?format=hosts >> /etc/hosts',
    ],
    endpoint: '/api/v1/blocklist/ips',
    method: 'GET',
    statusKey: 'firewall',
  },
  {
    id: 'firewall-import',
    name: 'Firewall Import',
    icon: '📥',
    description: 'Import your existing firewall blocklist IPs into Neev for tracking',
    category: 'firewall',
    setupSteps: [
      'Export your current firewall rules:',
      'iptables -L INPUT -n | grep DROP | awk \'{print $5}\' > blocked.txt',
      'Import into Neev:',
      'curl -X POST "http://YOUR_HOST:8000/api/v1/blocklist/import?source=my-firewall" \\',
      '  --data-binary @blocked.txt',
    ],
    endpoint: '/api/v1/blocklist/import',
    method: 'POST',
    statusKey: 'firewall-import',
  },
  {
    id: 'webhook',
    name: 'Generic Webhook',
    icon: '🔗',
    description: 'Receive JSON logs from any tool (cloud services, custom apps, etc.)',
    category: 'custom',
    setupSteps: [
      'Any tool can POST JSON to:',
      'POST http://YOUR_HOST:8000/api/v1/integrations/webhook/{your-tool-name}',
      'Body: {"src_ip":"1.2.3.4", "domain":"evil.com"}',
      '',
      'Also supports CEF format:',
      'POST http://YOUR_HOST:8000/api/v1/integrations/cef/{source-name}',
    ],
    endpoint: '/api/v1/integrations/webhook/{source}',
    method: 'POST',
    statusKey: 'webhook',
  },
]

const CATEGORIES = {
  all: 'All Integrations',
  siem: 'SIEM',
  ids: 'IDS/IPS',
  'threat-intel': 'Threat Intel',
  soar: 'SOAR',
  firewall: 'Firewall',
  custom: 'Custom',
}

export default function IntegrationsPanel({ axiosClient }) {
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [expandedId, setExpandedId] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const [importText, setImportText] = useState('')
  const [importSource, setImportSource] = useState('my-firewall')
  const [blocklistFormat, setBlocklistFormat] = useState('iptables')
  const [minScore, setMinScore] = useState(30)
  const [blocklistOutput, setBlocklistOutput] = useState('')
  const [copied, setCopied] = useState(null)
  const [isTesting, setIsTesting] = useState(false)
  const [isGenerating, setIsGenerating] = useState(false)
  const [isImporting, setIsImporting] = useState(false)

  const filteredIntegrations =
    selectedCategory === 'all'
      ? INTEGRATIONS
      : INTEGRATIONS.filter((i) => i.category === selectedCategory)

  async function testEndpoint(integration) {
    setIsTesting(true)
    try {
      const url = integration.endpoint.replace('/api/v1', '').replace('{log_type}', 'dns').replace('{source}', 'test')
      let res
      if (integration.method === 'GET') {
        res = await axiosClient.get(url)
      } else {
        res = await axiosClient.post(url, { test_event: "connection_check" })
      }
      setTestResult({ status: 'success', data: res.data })
    } catch (err) {
      setTestResult({ status: 'error', message: err.response?.data?.detail || err.message })
    }
    setIsTesting(false)
    setTimeout(() => setTestResult(null), 5000)
  }

  async function fetchBlocklist() {
    setIsGenerating(true)
    try {
      const isDomainFormat = ['hosts', 'unbound'].includes(blocklistFormat)
      const endpoint = isDomainFormat ? '/blocklist/domains' : '/blocklist/ips'
      const res = await axiosClient.get(endpoint, {
        params: { format: blocklistFormat, min_score: minScore },
      })
      setBlocklistOutput(res.data || '# No indicators found matching criteria')
    } catch (err) {
      setBlocklistOutput('Error fetching blocklist: ' + err.message)
    }
    setIsGenerating(false)
  }

  async function importBlocklist() {
    setIsImporting(true)
    try {
      const res = await axiosClient.post(
        `/blocklist/import?source=${importSource}`,
        importText,
        { headers: { 'Content-Type': 'text/plain' } }
      )
      setTestResult({ status: 'success', data: res.data })
      setImportText('')
    } catch (err) {
      setTestResult({ status: 'error', message: err.response?.data?.detail || err.message })
    }
    setIsImporting(false)
    setTimeout(() => setTestResult(null), 5000)
  }

  function copyToClipboard(text, id) {
    navigator.clipboard.writeText(text)
    setCopied(id)
    setTimeout(() => setCopied(null), 2000)
  }

  function getEndpointUrl(endpoint) {
    return window.location.origin.replace(/:\d+$/, ':8000') + endpoint
  }

  return (
    <div className="space-y-6">
      {/* Category Filter */}
      <div className="flex flex-wrap gap-2 mb-6">
        {Object.entries(CATEGORIES).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setSelectedCategory(key)}
            className={`px-4 py-2 rounded-xl text-sm font-medium transition ${
              selectedCategory === key
                ? 'bg-primary text-white shadow-md'
                : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 hover:border-slate-300'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Integration Cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {filteredIntegrations.map((integration) => (
          <div key={integration.id} className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition group overflow-hidden">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-slate-50 flex items-center justify-center border border-slate-100 text-xl shadow-sm">
                  {integration.icon}
                </div>
                <div>
                  <h3 className="font-bold text-slate-900">{integration.name}</h3>
                  <p className="text-xs text-slate-500 mt-0.5 line-clamp-2 pr-4">{integration.description}</p>
                </div>
              </div>
              <button
                onClick={() =>
                  setExpandedId(expandedId === integration.id ? null : integration.id)
                }
                className={`text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors ${
                  expandedId === integration.id 
                    ? 'bg-slate-100 text-slate-700' 
                    : 'bg-accent/10 text-accent hover:bg-accent/20'
                }`}
              >
                {expandedId === integration.id ? 'Hide' : 'Configure'}
              </button>
            </div>

            {integration.endpoint && (
              <div className="mt-4 flex items-center gap-2 bg-slate-50 p-2 rounded-lg border border-slate-100">
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded tracking-wide ${
                    integration.method === 'GET'
                      ? 'bg-emerald-100 text-emerald-700'
                      : 'bg-blue-100 text-blue-700'
                  }`}
                >
                  {integration.method}
                </span>
                <code className="text-[11px] text-slate-600 truncate flex-1 font-mono">
                  {integration.endpoint}
                </code>
                <button
                  onClick={() => copyToClipboard(getEndpointUrl(integration.endpoint), integration.id)}
                  className="text-slate-400 hover:text-accent flex-shrink-0 relative group/tooltip"
                  title="Copy Endpoint URL"
                >
                  <svg xmlns="http://www.w3.org/EU/00/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  {copied === integration.id && (
                    <span className="absolute -top-8 -left-3 bg-slate-800 text-white text-[10px] px-2 py-1 rounded shadow-lg whitespace-nowrap">
                      Copied!
                    </span>
                  )}
                </button>
              </div>
            )}

            {/* Expanded Setup */}
            {expandedId === integration.id && (
              <div className="mt-4 pt-4 border-t border-slate-100 animate-in fade-in slide-in-from-top-2 duration-200">
                <h4 className="text-sm font-semibold mb-2 text-slate-900">Setup Instructions</h4>
                <div className="bg-[#0f172a] text-[#4ade80] rounded-xl p-4 text-[11px] font-mono overflow-x-auto shadow-inner">
                  {integration.setupSteps.map((step, i) => (
                    <div key={i} className={step === '' ? 'h-2' : 'whitespace-pre relative pl-4 opacity-90'}>
                      {step !== '' && <span className="absolute left-0 text-slate-500 select-none">$</span>}
                      {step}
                    </div>
                  ))}
                </div>
                {integration.endpoint && (
                  <button
                    onClick={() => testEndpoint(integration)}
                    disabled={isTesting}
                    className="mt-4 w-full text-xs font-semibold bg-accent text-white px-4 py-2.5 rounded-xl transition-all shadow-sm hover:shadow-md hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {isTesting ? (
                      <><svg className="animate-spin h-3 w-3 text-white" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Testing...</>
                    ) : (
                      'Pysical Test Connection'
                    )}
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Test Result popup */}
      {testResult && (
        <div
          className={`fixed bottom-6 right-6 p-4 rounded-xl text-sm shadow-xl z-50 max-w-sm animate-in slide-in-from-bottom-5 ${
            testResult.status === 'success'
              ? 'bg-emerald-50 text-emerald-800 border-l-4 border-emerald-500'
              : 'bg-red-50 text-red-800 border-l-4 border-red-500'
          }`}
        >
          <div className="flex items-center gap-2 font-bold mb-1">
             {testResult.status === 'success' ? '✅ Success' : '❌ Error'}
          </div>
          {testResult.status === 'success' ? (
            <p className="text-xs truncate opacity-90">Connected successfully. Data structured perfectly.</p>
          ) : (
            <span className="text-xs">{testResult.message}</span>
          )}
        </div>
      )}

      {/* Utilities Grid */}
      <div className="grid gap-6 xl:grid-cols-2 mt-8">
        
        {/* Firewall Blocklist Export Section */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-4 mb-6">
            <div className="w-12 h-12 rounded-full bg-orange-50 flex items-center justify-center text-2xl border border-orange-100">🔥</div>
            <div>
              <h2 className="text-lg font-bold text-slate-900">Firewall Export</h2>
              <p className="text-xs text-slate-500 mt-0.5">Generate production-ready blocklists dynamically</p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 mb-5">
            <div>
              <label className="text-xs font-semibold text-slate-700 uppercase tracking-wider">Format</label>
              <select
                value={blocklistFormat}
                onChange={(e) => setBlocklistFormat(e.target.value)}
                className="mt-1.5 w-full rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 text-sm font-medium focus:ring-2 focus:ring-accent focus:border-accent transition-shadow"
              >
                <optgroup label="IP Blocklist">
                  <option value="plain">Plain IPs (list)</option>
                  <option value="iptables">iptables rules</option>
                  <option value="nftables">nftables set</option>
                  <option value="pf">pf rules</option>
                </optgroup>
                <optgroup label="Domain Sinkhole">
                  <option value="hosts">/etc/hosts</option>
                  <option value="unbound">Unbound DNS</option>
                </optgroup>
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-700 uppercase tracking-wider">Minimum Score</label>
              <input
                type="number"
                value={minScore}
                onChange={(e) => setMinScore(Number(e.target.value))}
                className="mt-1.5 w-full rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 text-sm font-medium focus:ring-2 focus:ring-accent focus:border-accent transition-shadow"
                min="0"
                max="100"
              />
            </div>
          </div>
          <button
            onClick={fetchBlocklist}
            disabled={isGenerating}
            className="w-full bg-slate-900 text-white px-4 py-2.5 rounded-xl text-sm font-semibold hover:bg-slate-800 transition-colors shadow flex items-center justify-center gap-2 disabled:opacity-70"
          >
            {isGenerating ? 'Generating...' : 'Generate Blocklist Deployment'}
          </button>

          {/* Code Viewer */}
          {blocklistOutput && (
            <div className="mt-5 animate-in fade-in slide-in-from-bottom-2">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2.5 py-1 rounded-full">
                  {blocklistOutput.split('\n').filter(l => l.trim() && !l.startsWith('#')).length} Rules Applied
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => copyToClipboard(blocklistOutput, 'blocklist')}
                    className="text-xs font-semibold text-slate-600 hover:text-accent transition-colors px-2 py-1 rounded hover:bg-slate-100"
                  >
                    {copied === 'blocklist' ? 'Copied!' : 'Copy snippet'}
                  </button>
                  <button
                    onClick={() => {
                      const blob = new Blob([blocklistOutput], { type: 'text/plain' })
                      const url = URL.createObjectURL(blob)
                      const a = document.createElement('a')
                      a.href = url
                      a.download = `blocklist.${['hosts', 'unbound', 'plain'].includes(blocklistFormat) ? 'txt' : 'rules'}`
                      a.click()
                    }}
                    className="text-xs font-semibold bg-primary/10 text-primary hover:bg-primary/20 transition-colors px-3 py-1 rounded"
                  >
                    Download raw
                  </button>
                </div>
              </div>
              <pre className="bg-[#0f172a] text-[#4ade80] rounded-xl p-4 text-[11px] font-mono overflow-auto h-48 shadow-inner border-t-[3px] border-slate-800">
                {blocklistOutput}
              </pre>
            </div>
          )}
        </div>

        {/* Firewall Import Section */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-4 mb-6">
            <div className="w-12 h-12 rounded-full bg-blue-50 flex items-center justify-center text-2xl border border-blue-100">📥</div>
            <div>
              <h2 className="text-lg font-bold text-slate-900">Firewall Import</h2>
              <p className="text-xs text-slate-500 mt-0.5">Ingest local blocks into intelligence stream</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-700 uppercase tracking-wider">Source Label</label>
              <input
                type="text"
                value={importSource}
                onChange={(e) => setImportSource(e.target.value)}
                className="mt-1.5 w-full rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 text-sm font-medium focus:ring-2 focus:ring-accent focus:border-accent transition-shadow"
                placeholder="e.g. pfSense-Headquarters"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-700 uppercase tracking-wider flex justify-between">
                <span>Indicators Data</span>
                <span className="text-slate-400 font-normal normal-case">One per line</span>
              </label>
              <textarea
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                className="mt-1.5 w-full rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm font-mono h-32 focus:ring-2 focus:ring-accent focus:border-accent transition-shadow shadow-inner"
                placeholder={"# Example data:\n1.2.3.4\n5.6.7.8\nmalicious-domain.com"}
              />
            </div>
          </div>
          <button
            onClick={importBlocklist}
            disabled={!importText.trim() || isImporting}
            className="mt-5 w-full bg-primary text-white px-6 py-2.5 rounded-xl text-sm font-semibold hover:bg-blue-700 transition-colors shadow flex justify-center items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isImporting ? 'Ingesting Data...' : 'Import to Intelligence Engine'}
          </button>
        </div>
      </div>

      {/* Quick Reference */}
      <div className="card">
        <h2 className="text-xl font-semibold mb-4">Quick Integration Reference</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead className="bg-slate-50">
              <tr>
                <th className="px-4 py-3 text-left font-semibold text-slate-600">Tool</th>
                <th className="px-4 py-3 text-left font-semibold text-slate-600">Direction</th>
                <th className="px-4 py-3 text-left font-semibold text-slate-600">Protocol</th>
                <th className="px-4 py-3 text-left font-semibold text-slate-600">What Flows</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-slate-700">
              <tr>
                <td className="px-4 py-3 font-medium">Wazuh</td>
                <td className="px-4 py-3">Wazuh → Neev</td>
                <td className="px-4 py-3">HTTP POST (webhook)</td>
                <td className="px-4 py-3">Alerts, source IPs, hashes, domains</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">Suricata</td>
                <td className="px-4 py-3">Suricata → Neev</td>
                <td className="px-4 py-3">HTTP POST (EVE JSON)</td>
                <td className="px-4 py-3">IDS alerts, DNS, TLS, HTTP, file hashes</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">Zeek</td>
                <td className="px-4 py-3">Zeek → Neev</td>
                <td className="px-4 py-3">HTTP POST (JSON logs)</td>
                <td className="px-4 py-3">Connections, DNS, HTTP, SSL, files, notices</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">MISP</td>
                <td className="px-4 py-3">Neev ↔ MISP</td>
                <td className="px-4 py-3">REST API (bidirectional)</td>
                <td className="px-4 py-3">IOCs (IPs, domains, hashes, URLs)</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">TheHive</td>
                <td className="px-4 py-3">Neev → TheHive</td>
                <td className="px-4 py-3">REST API (push)</td>
                <td className="px-4 py-3">Alerts, cases, observables</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">Firewall</td>
                <td className="px-4 py-3">Neev → Firewall</td>
                <td className="px-4 py-3">HTTP GET (pull)</td>
                <td className="px-4 py-3">IP blocklists, domain blocklists</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">Firewall</td>
                <td className="px-4 py-3">Firewall → Neev</td>
                <td className="px-4 py-3">HTTP POST (import)</td>
                <td className="px-4 py-3">Existing blocked IPs for tracking</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-medium">Any Tool</td>
                <td className="px-4 py-3">Tool → Neev</td>
                <td className="px-4 py-3">HTTP POST (webhook/CEF)</td>
                <td className="px-4 py-3">JSON payloads, CEF logs</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
