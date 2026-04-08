import { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import IndicatorTable from './components/IndicatorTable'
import ThreatScoreChart from './components/ThreatScoreChart'
import AlertsPanel from './components/AlertsPanel'
import RelationshipGraph from './components/RelationshipGraph'
import GeoMapPanel from './components/GeoMapPanel'
import IntegrationsPanel from './components/IntegrationsPanel'
import SourcesPanel from './components/SourcesPanel'
import LoginPage from './components/LoginPage'
import SignupPage from './components/SignupPage'
import OAuthCallback from './components/OAuthCallback'
import SearchPanel from './components/SearchPanel'
import AIPanel from './components/AIPanel'
import AttackCoverage from './components/AttackCoverage'
import ExportPanel from './components/ExportPanel'
import AdminPanel from './components/AdminPanel'
import RealtimeFeed from './components/RealtimeFeed'

const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

const TABS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2l-7-7-7 7m14-4v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { id: 'alerts', label: 'Alerts', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V6a1 1 0 00-1-1H9l-1.225-1.225a2.032 2.032 0 00-.59-.59V4a1 1 0 00-1-1H5a1 1 0 00-1 1v1a2 2 0 002 2h1m4 0V4m0 10.159A1.5 1.5 0 0118 15.659V19a1 1 0 01-1 1h-4a1 1 0 01-1-1v-1m5-10v10' },
  { id: 'search', label: 'Search', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7' },
  { id: 'attack', label: 'ATT&CK', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
  { id: 'ai', label: 'AI Analysis', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
  { id: 'export', label: 'Export', icon: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4' },
  { id: 'sources', label: 'Feeds', icon: 'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 11a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v1H7V8z' },
  { id: 'integrations', label: 'Integrations', icon: 'M11 4a2 2 0 114 0v1a2 2 0 011 2v5a2 2 0 01-2 2h-1a2 2 0 01-2-2v-5a2 2 0 01-1-2V7a2 2 0 114 0v-1M9 20h6' },
  { id: 'admin', label: 'Admin', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z' },
]

function App() {
  const [token, setToken] = useState(localStorage.getItem('neev_token') || '')
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('neev_user')
    return saved ? JSON.parse(saved) : null
  })
  const [authPage, setAuthPage] = useState('login')
  const [stats, setStats] = useState(null)
  const [indicators, setIndicators] = useState([])
  const [sources, setSources] = useState(['all'])
  const [sourceFilter, setSourceFilter] = useState('all')
  const [alerts, setAlerts] = useState([])
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('dashboard')
  const [selectedIndicators, setSelectedIndicators] = useState([])
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [showUserDropdown, setShowUserDropdown] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const [showQuickActions, setShowQuickActions] = useState(false)
  const [toast, setToast] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    const path = window.location.pathname
    const oauthMatch = path.match(/\/auth\/callback\/(google|github|microsoft)/)
    if (oauthMatch) setAuthPage(`oauth:${oauthMatch[1]}`)
  }, [])

  const axiosClient = useMemo(() => {
    const instance = axios.create({ baseURL: apiUrl })
    if (token) instance.defaults.headers.common.Authorization = `Bearer ${token}`
    instance.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          // Prevent aggressive auto-logout if the user was just running "Test Connection" on a webhook integration
          const isWebhookTest = error.response?.data?.detail === "Invalid or missing X-Webhook-Token header"
          
          if (!isWebhookTest) {
            localStorage.removeItem('neev_token')
            localStorage.removeItem('neev_user')
            window.location.reload()
          }
        }
        return Promise.reject(error)
      }
    )
    return instance
  }, [token])

  useEffect(() => {
    if (!token) return
    async function fetchDashboard() {
      try {
        const [statsRes, sourcesRes, alertsRes] = await Promise.all([
          axiosClient.get('/stats'),
          axiosClient.get('/sources'),
          axiosClient.get('/alerts?limit=25'),
        ])
        setStats(statsRes.data)
        setSources(['all', ...sourcesRes.data])
        setAlerts(alertsRes.data)
      } catch (err) { console.error(err); setError('Could not load dashboard data.') }
    }
    fetchDashboard()
  }, [token, axiosClient])

  useEffect(() => {
    if (!token) return
    async function fetchFilteredIndicators() {
      try {
        const params = { size: 100 }
        if (sourceFilter !== 'all') params.source = sourceFilter
        const response = await axiosClient.get('/indicators', { params })
        setIndicators(response.data)
      } catch (err) { console.error(err) }
    }
    fetchFilteredIndicators()
  }, [sourceFilter, token, axiosClient])

  function handleAuth(accessToken, userData) {
    setToken(accessToken)
    setUser(userData)
    localStorage.setItem('neev_token', accessToken)
    if (userData) localStorage.setItem('neev_user', JSON.stringify(userData))
    setAuthPage('dashboard')
    showToast('Welcome back!', 'success')
    window.history.replaceState({}, '', '/')
  }

  function handleLogout() {
    setToken(''); setUser(null)
    localStorage.removeItem('neev_token')
    localStorage.removeItem('neev_user')
    setStats(null); setIndicators([]); setAlerts([])
    setAuthPage('login')
  }

  function showToast(message, type = 'info') {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  if (!token) {
    if (authPage.startsWith('oauth:')) {
      return <OAuthCallback provider={authPage.split(':')[1]} onLogin={handleAuth} />
    }
    if (authPage === 'signup') {
      return <SignupPage onSignup={handleAuth} onSwitchToLogin={() => setAuthPage('login')} />
    }
    return <LoginPage onLogin={handleAuth} onSwitchToSignup={() => setAuthPage('signup')} />
  }

  const currentTab = TABS.find(t => t.id === activeTab)

  return (
    <div className="flex h-screen bg-slate-50">
      {/* Fixed Left Sidebar */}
      <aside className={`${sidebarCollapsed ? 'w-20' : 'w-64'} bg-slate-900 text-white flex flex-col transition-all duration-300 fixed left-0 top-0 h-full z-40`}>
        {/* Logo */}
        <div className="h-16 flex items-center px-4 border-b border-slate-700">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          {!sidebarCollapsed && (
            <div className="ml-3">
              <span className="font-bold text-lg">Neev TIP</span>
              <span className="block text-[9px] text-slate-400 uppercase tracking-widest">Threat Intel</span>
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {TABS.map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-3 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${
                activeTab === tab.id
                  ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-white'
              }`}>
              <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
              </svg>
              {!sidebarCollapsed && <span>{tab.label}</span>}
            </button>
          ))}
        </nav>

        {/* Collapse Button */}
        <div className="p-4 border-t border-slate-700">
          <button onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-sm text-slate-400 hover:bg-slate-800 hover:text-white transition-all">
            <svg className={`w-5 h-5 transition-transform ${sidebarCollapsed ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
            </svg>
            {!sidebarCollapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className={`flex-1 flex flex-col overflow-hidden transition-all duration-300 ${sidebarCollapsed ? 'ml-20' : 'ml-64'}`}>
        {/* Header */}
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0">
          {/* Breadcrumbs */}
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-500">Neev TIP</span>
            <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
            <span className="text-slate-900 font-medium">{currentTab?.label}</span>
          </div>

          {/* Search */}
          <div className="flex-1 max-w-md mx-8">
            <div className="relative">
              <svg className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input type="text" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Search indicators, IOCs..." className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-700 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all" />
              <kbd className="absolute right-3 top-1/2 -translate-y-1/2 px-2 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-100 rounded-lg border border-slate-200">⌘K</kbd>
            </div>
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-4">
            {/* Live indicator */}
            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-50 rounded-full border border-emerald-200">
              <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
              <span className="text-xs font-semibold text-emerald-600">{stats?.total_indicators ?? 0} IOCs</span>
            </div>

            {/* Notifications */}
            <div className="relative">
              <button onClick={() => setShowNotifications(!showNotifications)} className="relative p-2.5 text-slate-500 hover:bg-slate-100 hover:text-slate-700 rounded-xl transition-all">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V6a1 1 0 00-1-1H9l-1.225-1.225a2.032 2.032 0 00-.59-.59V4a1 1 0 00-1-1H5a1 1 0 00-1 1v1a2 2 0 002 2h1m4 0V4m0 10.159A1.5 1.5 0 0118 15.659V19a1 1 0 01-1 1h-4a1 1 0 01-1-1v-1m5-10v10" />
                </svg>
                <span className="absolute top-2 right-2 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-white"></span>
              </button>
              {showNotifications && (
                <div className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl border border-slate-200 shadow-xl z-50 animate-fade-in">
                  <div className="p-4 border-b border-slate-100">
                    <h3 className="font-semibold text-slate-900">Notifications</h3>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {alerts.slice(0, 5).map((alert, i) => (
                      <div key={i} className="p-4 border-b border-slate-50 hover:bg-slate-50 cursor-pointer transition-colors">
                        <div className="flex items-start gap-3">
                          <div className="w-2 h-2 rounded-full bg-amber-500 mt-2"></div>
                          <div>
                            <p className="text-sm font-medium text-slate-700">{alert.title || 'New Alert'}</p>
                            <p className="text-xs text-slate-500 mt-0.5">{alert.description || 'New threat indicator detected'}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                    {alerts.length === 0 && (
                      <div className="p-8 text-center text-slate-400 text-sm">No notifications</div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Quick Actions */}
            <button onClick={() => setShowQuickActions(!showQuickActions)} className="p-2.5 text-slate-500 hover:bg-slate-100 hover:text-slate-700 rounded-xl transition-all">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </button>

            {/* User Menu */}
            <div className="relative pl-4 border-l border-slate-200">
              <button onClick={() => setShowUserDropdown(!showUserDropdown)} className="flex items-center gap-3">
                {user?.avatar_url ? (
                  <img src={user.avatar_url} alt="" className="w-9 h-9 rounded-full ring-2 ring-slate-100" />
                ) : (
                  <div className="w-9 h-9 rounded-full bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center text-sm font-bold text-white shadow-md">
                    {(user?.full_name || user?.email || 'U')[0].toUpperCase()}
                  </div>
                )}
                <div className="text-left hidden lg:block">
                  <div className="text-sm font-semibold text-slate-700">{user?.full_name || 'User'}</div>
                  <div className="text-[10px] text-slate-400">{user?.role || 'analyst'}</div>
                </div>
                <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {showUserDropdown && (
                <div className="absolute right-0 top-full mt-2 w-48 bg-white rounded-xl border border-slate-200 shadow-xl z-50 animate-fade-in">
                  <div className="p-2">
                    <button onClick={handleLogout} className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-lg transition-colors">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                      </svg>
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto p-6">
          {/* Error Toast */}
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-sm text-red-600 flex items-center gap-2">
              <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              {error}
            </div>
          )}

          {/* Dashboard Tab */}
          {activeTab === 'dashboard' && (
            <div key={activeTab} className="space-y-6">
              {/* Stats Cards */}
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {[
                  { label: 'Total IOCs', value: stats?.total_indicators ?? '—', trend: '+12%', color: 'from-blue-500 to-blue-600', bg: 'bg-blue-50', text: 'text-blue-600' },
                  { label: 'Active Sources', value: sources.length - 1, trend: '+3', color: 'from-purple-500 to-purple-600', bg: 'bg-purple-50', text: 'text-purple-600' },
                  { label: 'Top Score', value: stats?.latest_indicators?.[0]?.confidence_score ?? '—', trend: 'High', color: 'from-amber-500 to-orange-500', bg: 'bg-amber-50', text: 'text-amber-600' },
                  { label: 'Countries', value: new Set(indicators.filter(i => i.geo?.country).map(i => i.geo.country)).size, trend: '+5', color: 'from-emerald-500 to-emerald-600', bg: 'bg-emerald-50', text: 'text-emerald-600' },
                ].map((stat) => (
                  <div key={stat.label} className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm hover:shadow-md transition-all">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{stat.label}</p>
                        <p className="text-3xl font-bold text-slate-900 mt-2">{stat.value}</p>
                      </div>
                      <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${stat.color} flex items-center justify-center text-white shadow-lg`}>
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={stat.label === 'Total IOCs' ? 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' : stat.label === 'Active Sources' ? 'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 11a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v1H7V8z' : stat.label === 'Top Score' ? 'M13 10V3L4 14h7v7l9-11h-7z' : 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2h1a2 2 0 012 2v1a2 2 0 01-2 2h-1a2 2 0 01-2-2v-1a2 2 0 00-2-2H3.055zm11.361-8.361a2 2 0 00-2.722 1.5L12 11.5l-1.694-1.25a2 2 0 00-2.722-1.5L3.055 12.5l1.694 1.25a2 2 0 002.722 1.5L12 15.5l1.694-1.25a2 2 0 002.722-1.5l-1.694-1.25z'} />
                        </svg>
                      </div>
                    </div>
                    <div className={`mt-4 text-xs font-semibold ${stat.text}`}>
                      <span className="inline-flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
                        </svg>
                        {stat.trend}
                      </span>
                      <span className="text-slate-400 ml-1">vs last week</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Source Filter */}
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Filter:</span>
                <div className="flex flex-wrap gap-2">
                  {sources.map((source) => (
                    <button key={source} onClick={() => setSourceFilter(source)}
                      className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all duration-200 ${
                        sourceFilter === source
                          ? 'bg-slate-900 text-white shadow-lg shadow-slate-900/20'
                          : 'bg-white text-slate-500 border border-slate-200 hover:border-slate-300 hover:shadow-md'
                      }`}>
                      {source === 'all' ? 'All Sources' : source}
                    </button>
                  ))}
                </div>
              </div>

              {/* Charts Row */}
              <div className="grid gap-6 xl:grid-cols-5">
                <div className="xl:col-span-3 bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-5">
                    <div>
                      <h2 className="text-base font-bold text-slate-900">Threat Score Timeline</h2>
                      <p className="text-xs text-slate-500 mt-0.5">AI-powered confidence scoring</p>
                    </div>
                    <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-50 text-blue-600 border border-blue-200">Live</span>
                  </div>
                  <ThreatScoreChart indicators={indicators} />
                </div>
                <div className="xl:col-span-2 bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-5">
                    <div>
                      <h2 className="text-base font-bold text-slate-900">Recent Alerts</h2>
                      <p className="text-xs text-slate-500 mt-0.5">Latest security events</p>
                    </div>
                    {alerts.length > 0 && (
                      <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-600 border border-amber-200">{alerts.length}</span>
                    )}
                  </div>
                  <AlertsPanel alerts={alerts} />
                </div>
              </div>

              {/* Table and Sidebar */}
              <div className="grid gap-6 xl:grid-cols-5">
                <div className="xl:col-span-3 bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-5">
                    <div>
                      <h2 className="text-base font-bold text-slate-900">Recent Indicators</h2>
                      <p className="text-xs text-slate-500 mt-0.5">Source: {sourceFilter}</p>
                    </div>
                  </div>
                  <IndicatorTable indicators={indicators} />
                </div>
                <div className="xl:col-span-2 space-y-6">
                  <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-5">
                      <h2 className="text-base font-bold text-slate-900">GeoIP Snapshot</h2>
                      <span className="text-xs text-slate-500">{indicators.filter(i => i.geo?.country).length} mapped</span>
                    </div>
                    <GeoMapPanel indicators={indicators} />
                  </div>
                  <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-5">
                      <h2 className="text-base font-bold text-slate-900">IOC Relationships</h2>
                      <span className="text-xs text-slate-500">{indicators.length} nodes</span>
                    </div>
                    <RelationshipGraph data={indicators} />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Search Tab */}
          {activeTab === 'search' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">Threat Search & Hunting</h1>
                <p className="text-sm text-slate-500 mt-1">Search IOCs, enrich indicators, and hunt for related threats.</p>
              </div>
              <SearchPanel axiosClient={axiosClient} />
            </div>
          )}

          {/* AI Analysis Tab */}
          {activeTab === 'ai' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">AI Threat Analysis</h1>
                <p className="text-sm text-slate-500 mt-1">Intelligent threat landscape analysis and recommendations.</p>
              </div>
              <AIPanel axiosClient={axiosClient} />
            </div>
          )}

          {/* Alerts Tab */}
          {activeTab === 'alerts' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">Real-time Alert Feed</h1>
                <p className="text-sm text-slate-500 mt-1">Live threat alerts from all sources and integrations.</p>
              </div>
              <div className="grid gap-6 xl:grid-cols-3">
                <div className="xl:col-span-2">
                  <RealtimeFeed axiosClient={axiosClient} />
                </div>
                <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                  <h3 className="text-base font-semibold mb-3">Alert Rules</h3>
                  <div className="space-y-2 text-sm">
                    {[
                      { name: 'High Severity IOC', desc: 'Score >= 70', color: 'bg-red-500' },
                      { name: 'Malware Hash', desc: 'Hash + malware tag', color: 'bg-orange-500' },
                      { name: 'Botnet C2', desc: 'C2 threat type', color: 'bg-red-500' },
                      { name: 'Ransomware', desc: 'Ransomware tag', color: 'bg-red-500' },
                      { name: 'Multi-Source', desc: '3+ sources', color: 'bg-amber-500' },
                      { name: 'Phishing URL', desc: 'URL + phishing', color: 'bg-amber-500' },
                    ].map(rule => (
                      <div key={rule.name} className="flex items-center gap-2 p-3 rounded-xl bg-slate-50">
                        <div className={`w-2 h-2 rounded-full ${rule.color}`}></div>
                        <div className="flex-1">
                          <div className="font-semibold text-xs text-slate-700">{rule.name}</div>
                          <div className="text-[10px] text-slate-400">{rule.desc}</div>
                        </div>
                        <span className="px-2 py-1 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-600 border border-emerald-200">Active</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ATT&CK Tab */}
          {activeTab === 'attack' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">MITRE ATT&CK Coverage</h1>
                <p className="text-sm text-slate-500 mt-1">Threat technique mapping and kill chain analysis.</p>
              </div>
              <AttackCoverage axiosClient={axiosClient} />
            </div>
          )}

          {/* Export Tab */}
          {activeTab === 'export' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">Export & Bulk Operations</h1>
                <p className="text-sm text-slate-500 mt-1">Download intelligence and perform bulk actions.</p>
              </div>
              <ExportPanel axiosClient={axiosClient} selectedIndicators={selectedIndicators} onClearSelection={() => setSelectedIndicators([])} />
            </div>
          )}

          {/* Admin Tab */}
          {activeTab === 'admin' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">Administration</h1>
                <p className="text-sm text-slate-500 mt-1">User management, system health, and audit logs.</p>
              </div>
              <AdminPanel axiosClient={axiosClient} />
            </div>
          )}

          {/* Threat Feeds Tab */}
          {activeTab === 'sources' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">Threat Feed Sources</h1>
                <p className="text-sm text-slate-500 mt-1">Manage external threat intelligence feeds. Free feeds work out of the box.</p>
              </div>
              <div className="grid gap-6 xl:grid-cols-2">
                <SourcesPanel axiosClient={axiosClient} />
                <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                  <h2 className="text-base font-bold text-slate-900 mb-4">Active Sources</h2>
                  <div className="space-y-2">
                    {sources.filter(s => s !== 'all').map(src => (
                      <div key={src} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
                        <div className="flex items-center gap-2.5">
                          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                          <span className="text-sm font-semibold text-slate-700">{src}</span>
                        </div>
                        <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-600 border border-emerald-200">Active</span>
                      </div>
                    ))}
                    {sources.filter(s => s !== 'all').length === 0 && (
                      <div className="text-center py-8 text-slate-400">
                        <svg className="w-10 h-10 mx-auto mb-2 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 11a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v1H7V8z" />
                        </svg>
                        <div className="text-sm">No active feeds yet</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* SIEM Integrations Tab */}
          {activeTab === 'integrations' && (
            <div key={activeTab}>
              <div className="mb-6">
                <h1 className="text-xl font-bold text-slate-900">SIEM Integrations</h1>
                <p className="text-sm text-slate-500 mt-1">Connect Neev TIP with your SOC tools.</p>
              </div>
              <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm mb-6">
                <h2 className="text-base font-bold text-slate-900 mb-4">Data Flow Architecture</h2>
                <div className="bg-slate-900 rounded-xl p-5 overflow-x-auto">
                  <pre className="text-[11px] text-blue-300 font-mono leading-relaxed">
{`  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │   Wazuh      │    │   Suricata   │    │     Zeek     │
    │   (SIEM)     │    │   (IDS/IPS)  │    │    (NSM)     │
    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
           │ webhook           │ EVE JSON          │ JSON logs
           ▼                   ▼                   ▼
    ┌────────────────────────────────────────────────────────┐
    │                    NEEV TIP                            │
    │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
    │  │ Receive │→ │ Enrich & │→ │  Score   │→ │ Export │ │
    │  └─────────┘  └──────────┘  └──────────┘  └───┬────┘ │
    └────────────────────────────────────────────────┼──────┘
           ▲                                        │
    ┌──────┴───────┐                        ┌───────▼──────┐
    │    MISP      │                        │   TheHive    │
    └──────────────┘                        └──────────────┘
           ▲                                        │
    ┌──────┴───────┐                        ┌───────▼──────┐
    │  Firewall    │←──── cron fetch ───────│    Cortex    │
    └──────────────┘                        └──────────────┘`}
                  </pre>
                </div>
              </div>
              <IntegrationsPanel axiosClient={axiosClient} />
            </div>
          )}
        </main>
      </div>

      {/* Toast Notification */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 animate-fade-in">
          <div className={`px-4 py-3 rounded-xl shadow-lg flex items-center gap-2 ${
            toast.type === 'success' ? 'bg-emerald-500 text-white' : toast.type === 'error' ? 'bg-red-500 text-white' : 'bg-slate-900 text-white'
          }`}>
            {toast.type === 'success' && (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            )}
            <span className="text-sm font-medium">{toast.message}</span>
          </div>
        </div>
      )}
    </div>
  )
}

export default App