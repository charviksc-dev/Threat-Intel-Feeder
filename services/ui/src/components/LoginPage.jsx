import { useState, useEffect } from 'react'

const OAUTH_CONFIG = {
  google: {
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
      </svg>
    ),
    label: 'Google',
  },
  github: {
    icon: (
      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
      </svg>
    ),
    label: 'GitHub',
  },
  microsoft: {
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24">
        <path fill="#F25022" d="M1 1h10v10H1z" />
        <path fill="#00A4EF" d="M1 13h10v10H1z" />
        <path fill="#7FBA00" d="M13 1h10v10H13z" />
        <path fill="#FFB900" d="M13 13h10v10H13z" />
      </svg>
    ),
    label: 'Microsoft',
  },
}

function getOAuthUrl(provider, clientId) {
  const redirectUri = `${window.location.origin}/auth/callback/${provider}`
  if (provider === 'google') {
    return `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid email profile' })}`
  }
  if (provider === 'github') {
    return `https://github.com/login/oauth/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, scope: 'user:email' })}`
  }
  if (provider === 'microsoft') {
    return `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid profile email User.Read' })}`
  }
  return '#'
}

export default function LoginPage({ onLogin, onSwitchToSignup }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [providers, setProviders] = useState({})
  const [showPassword, setShowPassword] = useState(false)

  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

  useEffect(() => {
    fetch(`${apiUrl}/auth/providers`).then(r => r.json()).then(d => setProviders(d.providers || {})).catch(() => {})
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch(`${apiUrl}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: email, password }),
      })
      if (!res.ok) {
        const data = await res.json()
        let message = 'Login failed'
        if (Array.isArray(data.detail)) message = data.detail.map(e => e.msg).join('. ')
        else if (typeof data.detail === 'string') message = data.detail
        throw new Error(message)
      }
      const data = await res.json()
      onLogin(data.access_token, data.user)
    } catch (err) {
      setError(err.message)
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen flex">
      {/* Left Panel */}
      <div className="hidden lg:flex lg:w-[480px] xl:w-[560px] flex-col justify-between p-12 text-white relative overflow-hidden"
        style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 40%, #0f172a 100%)' }}>
        {/* Decorative elements */}
        <div className="absolute top-0 left-0 w-full h-full opacity-5">
          <div className="absolute top-20 left-10 w-72 h-72 bg-blue-500 rounded-full blur-[100px]"></div>
          <div className="absolute bottom-20 right-10 w-96 h-96 bg-purple-500 rounded-full blur-[120px]"></div>
        </div>

        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center text-xl backdrop-blur-sm border border-white/10">
              <span className="material-symbols-outlined text-white">shield</span>
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight">Neev TIP</span>
              <span className="block text-[10px] text-primary-300 uppercase tracking-widest">Threat Intelligence</span>
            </div>
          </div>
        </div>

        <div className="relative z-10 space-y-8">
          <div>
            <h1 className="text-4xl font-bold leading-tight tracking-tight">
              Unified Threat<br />Intelligence Platform
            </h1>
            <p className="mt-4 text-primary-300 leading-relaxed">
              Centralize your threat intelligence. Ingest IOCs from 8+ feeds, integrate with SIEM tools, and automate blocking across your infrastructure.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            {[
              { value: '405+', label: 'Active IOCs', icon: '🎯' },
              { value: '8', label: 'Threat Feeds', icon: '📡' },
              { value: '9', label: 'SIEM Tools', icon: '🔗' },
              { value: '24/7', label: 'Monitoring', icon: '⚡' },
            ].map((stat) => (
              <div key={stat.label} className="bg-white/5 backdrop-blur-sm rounded-xl p-4 border border-white/5">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm">{stat.icon}</span>
                  <span className="text-xl font-bold">{stat.value}</span>
                </div>
                <div className="text-xs text-primary-300">{stat.label}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap gap-2">
            {['Wazuh', 'Suricata', 'Zeek', 'MISP', 'TheHive', 'Cortex', 'Firewall'].map(tool => (
              <span key={tool} className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/5 text-xs text-primary-200">
                {tool}
              </span>
            ))}
          </div>
        </div>

        <div className="relative z-10 text-xs text-primary-400">
          Enterprise-grade threat intelligence for SOC teams
        </div>
      </div>

      {/* Right Panel - Login Form */}
      <div className="flex-1 flex items-center justify-center p-8 bg-surface">
        <div className="w-full max-w-[400px] animate-fade-in">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="w-10 h-10 rounded-xl bg-primary-800 flex items-center justify-center text-xl">
              <span className="material-symbols-outlined text-white">shield</span>
            </div>
            <span className="text-xl font-bold text-primary-800">Neev TIP</span>
          </div>

          <div className="mb-8">
            <h2 className="text-2xl font-bold text-primary-800 tracking-tight">Welcome back</h2>
            <p className="text-primary-500 mt-1.5">Sign in to your SOC dashboard</p>
          </div>

          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-danger/10 border border-danger/20 text-sm text-danger flex items-start gap-2">
              <svg className="w-4 h-4 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <span>{error}</span>
            </div>
          )}

          {/* OAuth Buttons */}
          <div className="space-y-2.5 mb-6">
            {Object.entries(OAUTH_CONFIG).map(([provider, config]) => {
              const isEnabled = providers[provider]?.enabled
              return (
                <button
                  key={provider}
                  onClick={() => isEnabled && (window.location.href = getOAuthUrl(provider, providers[provider]?.client_id))}
                  disabled={!isEnabled}
                  className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl text-sm font-semibold border border-primary-200 bg-white hover:bg-primary-50 hover:border-primary-300 text-primary-700 transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed active:scale-[0.99]"
                >
                  {config.icon}
                  <span>Continue with {config.label}</span>
                  {!isEnabled && <span className="text-[10px] text-primary-400 ml-auto">not configured</span>}
                </button>
              )
            })}
          </div>

          <div className="relative mb-6">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-primary-200"></div></div>
            <div className="relative flex justify-center text-xs">
              <span className="px-3 bg-surface text-primary-400 font-medium">or continue with email</span>
            </div>
          </div>

          {/* Email/Password */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-primary-700 mb-1.5">Email address</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                className="input" placeholder="analyst@company.com" required />
            </div>
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-sm font-semibold text-primary-700">Password</label>
                <button type="button" className="text-xs text-accent hover:underline font-semibold">Forgot?</button>
              </div>
              <div className="relative">
                <input type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  className="input pr-12" placeholder="Enter your password" required />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-primary-400 hover:text-primary-600 font-semibold">
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>
            <button type="submit" disabled={loading}
              className="btn btn-primary w-full py-3.5 text-[15px]">
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                  Signing in...
                </span>
              ) : 'Sign in'}
            </button>
          </form>

          <p className="mt-8 text-center text-sm text-primary-500">
            Don't have an account?{' '}
            <button onClick={onSwitchToSignup} className="text-accent font-semibold hover:underline">Create account</button>
          </p>
        </div>
      </div>
    </div>
  )
}
