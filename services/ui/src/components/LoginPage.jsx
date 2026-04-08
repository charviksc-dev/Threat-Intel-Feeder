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
    <div className="min-h-screen flex bg-[#f8fafc] overflow-hidden font-['Plus_Jakarta_Sans',sans-serif]">
      {/* Left Panel - Immersive Security Portal */}
      <div className="hidden lg:flex lg:w-[480px] xl:w-[600px] flex-col justify-between p-12 text-white relative overflow-hidden shadow-2xl"
        style={{ background: 'linear-gradient(165deg, #020617 0%, #0f172a 60%, #1e293b 100%)' }}>
        
        {/* Animated Background Orbs */}
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
          <div className="absolute top-[-10%] left-[-10%] w-[60%] h-[60%] bg-sky-500/20 rounded-full blur-[120px] animate-pulse-soft"></div>
          <div className="absolute bottom-[0%] right-[-10%] w-[50%] h-[50%] bg-indigo-500/10 rounded-full blur-[100px]"></div>
          
          {/* Grid Pattern */}
          <div className="absolute inset-0 opacity-[0.03]" 
            style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, white 1px, transparent 0)', backgroundSize: '40px 40px' }}></div>
        </div>

        <div className="relative z-10">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-white/10 flex items-center justify-center text-2xl backdrop-blur-md border border-white/20 shadow-xl">
              <span className="material-symbols-outlined text-sky-400 font-bold">shield</span>
            </div>
            <div>
              <span className="text-2xl font-black tracking-tighter bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">NEEV TIP</span>
              <span className="block text-[10px] text-sky-400 font-black uppercase tracking-[0.3em] mt-0.5">Threat Intel Portal</span>
            </div>
          </div>
        </div>

        <div className="relative z-10 space-y-12">
          <div className="animate-slide-up">
            <h1 className="text-5xl font-extrabold leading-[1.1] tracking-tight">
              Defend with<br />
              <span className="text-sky-400">Intelligence.</span>
            </h1>
            <p className="mt-6 text-slate-400 text-lg leading-relaxed font-medium">
              The next generation of threat intelligence for elite SOC teams. Unified, automated, and battle-tested.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4 animate-slide-up" style={{ animationDelay: '0.1s' }}>
            {[
              { value: '1.2M+', label: 'IOC Patterns', icon: '🎯' },
              { value: '8', label: 'Global Feeds', icon: '📡' },
              { value: 'Realtime', label: 'SIEM Sync', icon: '⚡' },
              { value: 'Auto', label: 'Blocking', icon: '🛡️' },
            ].map((stat) => (
              <div key={stat.label} className="bg-white/5 backdrop-blur-sm rounded-2xl p-5 border border-white/10 group hover:bg-white/10 transition-all duration-300">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-xl group-hover:scale-125 transition-transform duration-300">{stat.icon}</span>
                  <span className="text-xl font-black">{stat.value}</span>
                </div>
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{stat.label}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap gap-2.5 animate-slide-up" style={{ animationDelay: '0.2s' }}>
            {['Wazuh', 'Suricata', 'Zeek', 'MISP', 'TheHive', 'Cortex'].map(tool => (
              <span key={tool} className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-[11px] font-bold text-slate-300 hover:text-sky-400 hover:bg-white/10 transition-all cursor-default">
                {tool}
              </span>
            ))}
          </div>
        </div>

        <div className="relative z-10 flex items-center gap-3 text-xs font-bold text-slate-500">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
          System Status: Operational
        </div>
      </div>

      {/* Right Panel - Premium Auth Card */}
      <div className="flex-1 flex items-center justify-center p-8 relative">
        {/* Decorative background for right panel */}
        <div className="absolute inset-0 opacity-[0.015] pointer-events-none" 
          style={{ backgroundImage: 'linear-gradient(45deg, #0f172a 25%, transparent 25%, transparent 50%, #0f172a 50%, #0f172a 75%, transparent 75%, transparent)', backgroundSize: '60px 60px' }}></div>

        <div className="w-full max-w-[420px] space-y-8 animate-fade-in relative z-10">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="w-12 h-12 rounded-2xl bg-slate-900 flex items-center justify-center text-2xl shadow-xl shadow-slate-900/20">
              <span className="material-symbols-outlined text-sky-400 font-bold">shield</span>
            </div>
            <div>
              <span className="text-xl font-black text-slate-900 tracking-tighter">NEEV TIP</span>
              <span className="block text-[8px] font-black text-sky-500 uppercase tracking-widest">Enterprise</span>
            </div>
          </div>

          <div className="text-center lg:text-left">
            <h2 className="text-3xl font-black text-slate-900 tracking-tight">Secure Access</h2>
            <p className="text-slate-500 mt-2 font-medium">Please enter your credentials to continue</p>
          </div>

          {error && (
            <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-sm text-rose-600 flex items-start gap-3 animate-shake font-bold">
              <span className="material-symbols-outlined text-[20px] mt-0.5">error</span>
              <span>{error}</span>
            </div>
          )}

          {/* Social Auth Grids */}
          <div className="grid grid-cols-3 gap-3">
            {Object.entries(OAUTH_CONFIG).map(([provider, config]) => {
              const isEnabled = providers[provider]?.enabled
              return (
                <button
                  key={provider}
                  onClick={() => isEnabled && (window.location.href = getOAuthUrl(provider, providers[provider]?.client_id))}
                  disabled={!isEnabled}
                  className="flex flex-col items-center justify-center gap-2 p-4 rounded-2xl border-2 border-slate-100 bg-white hover:border-sky-500/30 hover:bg-sky-50/30 transition-all duration-300 disabled:opacity-40 disabled:grayscale group active:scale-95"
                  title={isEnabled ? `Login with ${config.label}` : 'Not configured'}
                >
                  <div className="group-hover:scale-110 transition-transform">{config.icon}</div>
                  <span className="text-[10px] font-black uppercase text-slate-400 group-hover:text-slate-600 tracking-wider font-mono">{config.label}</span>
                </button>
              )
            })}
          </div>

          <div className="relative flex items-center">
            <div className="flex-1 border-t-2 border-slate-50"></div>
            <span className="px-4 text-[10px] font-black text-slate-400 uppercase tracking-widest bg-white">Or secure email</span>
            <div className="flex-1 border-t-2 border-slate-50"></div>
          </div>

          {/* Auth Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Email Identifier</label>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">alternate_email</span>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                  className="input pl-12" placeholder="analyst@neev.shield" required />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between ml-1">
                <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest">Access Key</label>
                <button type="button" className="text-[10px] text-sky-600 font-black uppercase tracking-wider hover:underline">Revoke Access?</button>
              </div>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">lock</span>
                <input type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  className="input pl-12 pr-12" placeholder="••••••••" required />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors">
                  <span className="material-symbols-outlined text-[20px]">{showPassword ? 'visibility_off' : 'visibility'}</span>
                </button>
              </div>
            </div>

            <button type="submit" disabled={loading}
              className="btn btn-primary w-full py-4 text-base font-black uppercase tracking-widest group bg-slate-900 border-2 border-slate-900 hover:bg-sky-500 hover:border-sky-500 shadow-2xl shadow-slate-900/20 hover:shadow-sky-500/40 relative overflow-hidden transition-all duration-300">
              <span className="relative z-10 flex items-center justify-center gap-3">
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                    Validating...
                  </>
                ) : (
                  <>
                    Initialize Session
                    <span className="material-symbols-outlined group-hover:translate-x-1 transition-transform">arrow_forward</span>
                  </>
                )}
              </span>
            </button>
          </form>

          <p className="text-center text-sm font-bold text-slate-500">
            Unauthorized?{' '}
            <button onClick={onSwitchToSignup} className="text-sky-600 hover:underline">Request Access Credentials</button>
          </p>

          <div className="pt-8 text-center">
            <div className="flex items-center justify-center gap-6 opacity-40 grayscale group-hover:grayscale-0 transition-all duration-500">
              <span className="material-symbols-outlined text-[32px]">verified_user</span>
              <span className="material-symbols-outlined text-[32px]">admin_panel_settings</span>
              <span className="material-symbols-outlined text-[32px]">vpn_lock</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
