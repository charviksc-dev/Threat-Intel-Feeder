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
    <div className="space-y-8 animate-fade-in">
      {/* Category Filter - Glassmorphic Tabs */}
      <div className="flex flex-wrap gap-2.5 p-1.5 bg-slate-200/40 backdrop-blur-md rounded-2xl border border-white/40 w-fit">
        {Object.entries(CATEGORIES).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setSelectedCategory(key)}
            className={`px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all duration-300 ${
              selectedCategory === key
                ? 'bg-slate-900 text-white shadow-xl shadow-slate-900/20 scale-105'
                : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Integration Cards - Premium Grid */}
      <div className="grid gap-6 md:grid-cols-2 2xl:grid-cols-3">
        {filteredIntegrations.map((integration) => (
          <div key={integration.id} 
            className={`group rounded-3xl border transition-all duration-500 overflow-hidden flex flex-col ${
              expandedId === integration.id 
                ? 'bg-white border-sky-200 shadow-2xl shadow-sky-500/10 ring-4 ring-sky-50/50' 
                : 'bg-white/70 backdrop-blur-sm border-slate-200 hover:border-sky-300/50 hover:shadow-xl hover:shadow-slate-200/50'
            }`}>
            
            <div className="p-6 flex-1">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-4">
                  <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-3xl shadow-inner border transition-transform duration-500 group-hover:scale-110 ${
                    expandedId === integration.id ? 'bg-sky-50 border-sky-100' : 'bg-slate-50 border-slate-100'
                  }`}>
                    {integration.icon}
                  </div>
                  <div>
                    <h3 className="font-black text-slate-900 tracking-tight text-lg">{integration.name}</h3>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[9px] font-black uppercase tracking-[0.15em] px-2 py-0.5 bg-slate-100 text-slate-500 rounded-lg">{integration.category}</span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setExpandedId(expandedId === integration.id ? null : integration.id)}
                  className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all duration-300 ${
                    expandedId === integration.id 
                      ? 'bg-slate-900 text-white rotate-180' 
                      : 'bg-slate-100 text-slate-400 hover:bg-sky-500 hover:text-white'
                  }`}
                >
                  <span className="material-symbols-outlined text-[20px]">expand_more</span>
                </button>
              </div>

              <p className="text-sm font-medium text-slate-500 leading-relaxed mb-6">
                {integration.description}
              </p>

              {integration.endpoint && (
                <div className="flex items-center gap-3 bg-slate-900/5 p-3 rounded-2xl border border-slate-900/5 font-mono group/code">
                  <span className={`text-[9px] font-black px-2 py-0.5 rounded-md ${
                    integration.method === 'GET' ? 'bg-emerald-500 text-white' : 'bg-sky-500 text-white'
                  }`}>
                    {integration.method}
                  </span>
                  <code className="text-[10px] text-slate-600 truncate flex-1 font-bold">
                    {integration.endpoint}
                  </code>
                  <button
                    onClick={() => copyToClipboard(getEndpointUrl(integration.endpoint), integration.id)}
                    className="text-slate-400 hover:text-sky-500 transition-colors"
                  >
                    <span className="material-symbols-outlined text-[18px]">
                      {copied === integration.id ? 'check' : 'content_copy'}
                    </span>
                  </button>
                </div>
              )}
            </div>

            {/* Expanded Setup - Console Style */}
            {expandedId === integration.id && (
              <div className="px-6 pb-6 animate-in slide-in-from-top-4 duration-500">
                <div className="space-y-4 pt-6 border-t border-slate-100">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-[11px] font-black text-slate-400 uppercase tracking-widest">Initialization Protocol</h4>
                    <span className="flex gap-1">
                      <span className="w-2 h-2 rounded-full bg-rose-400/20"></span>
                      <span className="w-2 h-2 rounded-full bg-amber-400/20"></span>
                      <span className="w-2 h-2 rounded-full bg-emerald-400/20"></span>
                    </span>
                  </div>
                  
                  <div className="bg-[#020617] rounded-3xl p-6 text-[11px] font-mono shadow-2xl border border-white/5 relative group/terminal">
                    <div className="absolute top-4 right-4 text-[10px] font-black text-slate-700 uppercase tracking-widest opacity-0 group-hover/terminal:opacity-100 transition-opacity">Read-only bash</div>
                    <div className="space-y-1.5 max-h-[240px] overflow-y-auto custom-scrollbar">
                      {integration.setupSteps.map((step, i) => (
                        <div key={i} className={`flex gap-3 ${step === '' ? 'h-4' : 'opacity-90'}`}>
                          {step !== '' && <span className="text-sky-500/50 shrink-0 select-none">[{i+1}]</span>}
                          <span className={`${step.startsWith('<') ? 'text-amber-400' : 'text-slate-300'} whitespace-pre`}>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {integration.endpoint && (
                    <button
                      onClick={() => testEndpoint(integration)}
                      disabled={isTesting}
                      className="w-full py-4 rounded-2xl font-black uppercase tracking-widest text-xs flex items-center justify-center gap-3 transition-all duration-300 relative overflow-hidden group/btn"
                    >
                      <div className="absolute inset-0 bg-slate-900 group-hover/btn:bg-sky-600 transition-colors"></div>
                      <span className="relative z-10 flex items-center justify-center gap-3 text-white">
                        {isTesting ? (
                          <>
                            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>
                            Verifying...
                          </>
                        ) : (
                          <>
                            Physical Handshake
                            <span className="material-symbols-outlined text-[18px] group-hover:translate-x-1 transition-transform">sensors</span>
                          </>
                        )}
                      </span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Utilities Grid - Premium Panels */}
      <div className="grid gap-8 2xl:grid-cols-2 mt-4">
        
        {/* Firewall Export Panel */}
        <div className="glass-panel p-8 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-orange-500/5 rounded-full blur-3xl -mr-16 -mt-16 group-hover:bg-orange-500/10 transition-colors duration-500"></div>
          
          <div className="flex items-center gap-6 mb-8">
            <div className="w-16 h-16 rounded-3xl bg-orange-500/10 flex items-center justify-center text-3xl border border-orange-500/20 shadow-xl shadow-orange-500/5">🔥</div>
            <div>
              <h2 className="text-2xl font-black text-slate-900 tracking-tight">Perimeter Export</h2>
              <p className="text-sm font-medium text-slate-500">Generate high-precision blocklists for security appliances</p>
            </div>
          </div>

          <div className="grid gap-6 sm:grid-cols-2 mb-8">
            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1 text-sky-600">Sync Format</label>
              <select
                value={blocklistFormat}
                onChange={(e) => setBlocklistFormat(e.target.value)}
                className="input cursor-pointer appearance-none bg-slate-50"
              >
                <optgroup label="Network Security" className="font-bold">
                  <option value="plain">IP Stream (CURL Friendly)</option>
                  <option value="iptables">Linux iptables</option>
                  <option value="nftables">Modern nftables</option>
                  <option value="pf">BSD / pfSense rules</option>
                </optgroup>
                <optgroup label="Application Layer" className="font-bold">
                  <option value="hosts">Static hosts override</option>
                  <option value="unbound">Unbound DNS Zone</option>
                </optgroup>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Threat Threshold</label>
              <div className="relative">
                <input
                  type="number"
                  value={minScore}
                  onChange={(e) => setMinScore(Number(e.target.value))}
                  className="input pl-10"
                  min="0"
                  max="100"
                />
                <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-[20px]">priority_high</span>
              </div>
            </div>
          </div>

          <button
            onClick={fetchBlocklist}
            disabled={isGenerating}
            className="btn btn-primary w-full py-4 text-sm font-black uppercase tracking-widest flex items-center justify-center gap-3 relative overflow-hidden bg-slate-900 border-2 border-slate-900 hover:bg-orange-600 hover:border-orange-600 shadow-2xl shadow-slate-900/10 transition-all duration-300"
          >
            {isGenerating ? (
              'Querying Threat Data...'
            ) : (
              <>
                Compute Deployment Rules
                <span className="material-symbols-outlined">terminal</span>
              </>
            )}
          </button>

          {/* Code Viewer Output */}
          {blocklistOutput && (
            <div className="mt-8 space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="flex items-center justify-between px-1">
                <div className="flex gap-3">
                  <span className="px-3 py-1 rounded-full bg-slate-100 text-[10px] font-black text-slate-600 uppercase tracking-tighter">
                    {blocklistOutput.split('\n').filter(l => l.trim() && !l.startsWith('#')).length} Nodes Identified
                  </span>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      const blob = new Blob([blocklistOutput], { type: 'text/plain' })
                      const url = URL.createObjectURL(blob)
                      const a = document.createElement('a')
                      a.href = url
                      a.download = `neev_blocklist_${blocklistFormat}.rules`
                      a.click()
                    }}
                    className="p-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-sky-50 hover:text-sky-600 hover:border-sky-200 transition-all"
                    title="Download Protocol"
                  >
                    <span className="material-symbols-outlined text-[20px]">download</span>
                  </button>
                  <button
                    onClick={() => copyToClipboard(blocklistOutput, 'blocklist')}
                    className="px-4 py-2 rounded-xl bg-slate-900 text-white text-[10px] font-black uppercase tracking-widest hover:bg-sky-600 transition-colors"
                  >
                    {copied === 'blocklist' ? 'Copied' : 'Transfer to Clipboard'}
                  </button>
                </div>
              </div>
              <div className="bg-[#020617] rounded-3xl p-6 shadow-2xl border border-white/5 relative overflow-hidden group/out">
                <div className="absolute top-0 right-0 w-32 h-32 bg-sky-500/10 blur-[80px] -mr-16 -mt-16"></div>
                <pre className="text-[#4ade80] text-[11px] font-mono h-[320px] overflow-auto custom-scrollbar relative z-10">
                  {blocklistOutput}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Firewall Import Panel */}
        <div className="glass-panel p-8 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-sky-500/5 rounded-full blur-3xl -mr-16 -mt-16 group-hover:bg-sky-500/10 transition-colors duration-500"></div>

          <div className="flex items-center gap-6 mb-8">
            <div className="w-16 h-16 rounded-3xl bg-sky-500/10 flex items-center justify-center text-3xl border border-sky-500/20 shadow-xl shadow-sky-500/5">📥</div>
            <div>
              <h2 className="text-2xl font-black text-slate-900 tracking-tight">Security Ingestion</h2>
              <p className="text-sm font-medium text-slate-500">Import existing threat identifiers into the sync engine</p>
            </div>
          </div>

          <div className="space-y-6">
            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Asset Source Label</label>
              <div className="relative group/field">
                <input
                  type="text"
                  value={importSource}
                  onChange={(e) => setImportSource(e.target.value)}
                  className="input pl-12"
                  placeholder="e.g. Edge-Router-East"
                />
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within/field:text-sky-500 transition-colors">dns</span>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1 flex justify-between">
                <span>Identifiers Batch</span>
                <span className="text-[9px] text-slate-400 font-bold uppercase tracking-widest">LF/EOF Delimited</span>
              </label>
              <div className="relative group/area">
                <textarea
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                  className="input min-h-[160px] font-mono p-5 leading-relaxed bg-[#fcfdfe]"
                  placeholder={"1.2.3.4\n5.6.7.8\n# malware-nexus.xyz"}
                />
                <div className="absolute right-4 bottom-4 p-2 rounded-lg bg-slate-100 text-[10px] font-black text-slate-400 uppercase">Input Buffer</div>
              </div>
            </div>
          </div>

          <button
            onClick={importBlocklist}
            disabled={!importText.trim() || isImporting}
            className="btn btn-primary w-full py-4 text-sm font-black uppercase tracking-widest flex items-center justify-center gap-3 relative overflow-hidden bg-slate-900 border-2 border-slate-900 hover:bg-sky-600 hover:border-sky-600 shadow-2xl shadow-slate-900/10 transition-all duration-300 mt-8 disabled:opacity-40"
          >
            {isImporting ? (
              'Processing Data Packet...'
            ) : (
              <>
                Synchronize Ingestion
                <span className="material-symbols-outlined">upload</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Quick Reference - High Contrast Table */}
      <div className="glass-panel overflow-hidden border-slate-200 mt-4">
        <div className="px-8 py-6 border-b border-slate-100 flex items-center justify-between">
          <h2 className="text-xl font-black text-slate-900 tracking-tight">Data Flow Protocols</h2>
          <span className="px-3 py-1 rounded-lg bg-emerald-500/10 text-[10px] font-black text-emerald-600 uppercase tracking-widest border border-emerald-500/20">Active Schema</span>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="bg-slate-50">
                <th className="px-8 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Secure Appliance</th>
                <th className="px-8 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Vector</th>
                <th className="px-8 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Communication Layer</th>
                <th className="px-8 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Payload Profile</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {[
                { tool: 'Wazuh', dir: 'INBOUND', proto: 'HTTP/HTTPS WEBHOOK', data: 'Managed Node Alerts, File Metadata' },
                { tool: 'Suricata', dir: 'INBOUND', proto: 'EVE JSON STREAM', data: 'NTA Alerts, TLS/DNS Artifacts' },
                { tool: 'Zeek', dir: 'INBOUND', proto: 'JSON LOG BATCH', data: 'Session Observables, Notice Logs' },
                { tool: 'MISP', dir: 'RECURSIVE', proto: 'REST API SYNC', data: 'IOC Clusters, Shared Intel' },
                { tool: 'TheHive', dir: 'OUTBOUND', proto: 'ELASTIC CASE API', data: 'Escalated Alerts, Case Files' },
                { tool: 'Firewall', dir: 'SYNC', proto: 'SECURE PULL/PUSH', data: 'Realtime IP/Domain Blocklists' },
              ].map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-50/50 transition-colors">
                  <td className="px-8 py-5 font-black text-slate-900">{row.tool}</td>
                  <td className="px-8 py-5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-black ${
                      row.dir === 'INBOUND' ? 'bg-sky-100 text-sky-700' : 
                      row.dir === 'OUTBOUND' ? 'bg-orange-100 text-orange-700' : 'bg-emerald-100 text-emerald-700'
                    }`}>{row.dir}</span>
                  </td>
                  <td className="px-8 py-5 font-mono text-xs text-slate-500 uppercase font-black">{row.proto}</td>
                  <td className="px-8 py-5 text-slate-600 font-medium">{row.data}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Success/Error Notifiers */}
      {testResult && (
        <div className="fixed bottom-12 right-12 z-[100] animate-in slide-in-from-right-12 duration-500">
          <div className={`p-6 rounded-3xl shadow-2xl backdrop-blur-xl border flex items-center gap-5 min-w-[320px] ${
            testResult.status === 'success' 
              ? 'bg-white border-emerald-200' 
              : 'bg-white border-rose-200'
          }`}>
            <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-2xl ${
              testResult.status === 'success' ? 'bg-emerald-100 text-emerald-600 shadow-lg shadow-emerald-500/20' : 'bg-rose-100 text-rose-600 shadow-lg shadow-rose-500/20'
            }`}>
              <span className="material-symbols-outlined">{testResult.status === 'success' ? 'task_alt' : 'error'}</span>
            </div>
            <div>
              <div className="font-black text-slate-900 uppercase tracking-widest text-[11px] mb-1">Response Protocol</div>
              <p className="text-sm font-bold text-slate-600">{testResult.status === 'success' ? 'Synchronized and verified.' : (testResult.message || 'Operation failed')}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
