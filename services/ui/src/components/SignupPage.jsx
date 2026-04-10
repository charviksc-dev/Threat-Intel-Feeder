import { useEffect, useState } from 'react'

export default function SignupPage({ onSignup, onSwitchToLogin }) {
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('analyst')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [optionsLoading, setOptionsLoading] = useState(true)
  const [signupOptions, setSignupOptions] = useState({
    admin_exists: true,
    allowed_roles: ['analyst'],
    privileged_roles: ['admin', 'soc_manager'],
    default_role: 'analyst',
  })
  const [showPassword, setShowPassword] = useState(false)

  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'
  const roleLabels = {
    admin: 'Admin',
    analyst: 'Analyst',
    soc_manager: 'SOC Manager',
    viewer: 'Viewer',
    observer: 'Observer',
  }

  useEffect(() => {
    let cancelled = false
    async function loadSignupOptions() {
      try {
        const res = await fetch(`${apiUrl}/auth/signup-options`)
        if (!res.ok) throw new Error('Failed to load signup options')
        const data = await res.json()
        if (cancelled) return
        const allowedRoles = Array.isArray(data.allowed_roles) && data.allowed_roles.length
          ? data.allowed_roles
          : ['analyst']
        setSignupOptions({
          admin_exists: Boolean(data.admin_exists),
          allowed_roles: allowedRoles,
          privileged_roles: Array.isArray(data.privileged_roles) ? data.privileged_roles : ['admin', 'soc_manager'],
          default_role: data.default_role || 'analyst',
        })
        setRole(prev => (allowedRoles.includes(prev) ? prev : (data.default_role || allowedRoles[0] || 'analyst')))
      } catch (_) {
        if (cancelled) return
        setSignupOptions({
          admin_exists: true,
          allowed_roles: ['analyst'],
          privileged_roles: ['admin', 'soc_manager'],
          default_role: 'analyst',
        })
      } finally {
        if (!cancelled) setOptionsLoading(false)
      }
    }
    loadSignupOptions()
    return () => { cancelled = true }
  }, [apiUrl])

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (password !== confirmPassword) { setError('Passwords do not match'); return }
    if (password.length < 8) { setError('Password must be at least 8 characters'); return }
    setLoading(true)
    try {
      const res = await fetch(`${apiUrl}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, full_name: fullName, role }),
      })
      if (!res.ok) {
        const data = await res.json()
        let message = 'Signup failed'
        if (Array.isArray(data.detail)) message = data.detail.map(e => e.msg).join('. ')
        else if (typeof data.detail === 'string') message = data.detail
        throw new Error(message)
      }
      const data = await res.json()
      onSignup(data.access_token, data.user)
    } catch (err) { setError(err.message) }
    setLoading(false)
  }

  function getPasswordStrength(pw) {
    if (!pw) return { level: 0, label: '', color: '' }
    let score = 0
    if (pw.length >= 8) score++
    if (pw.length >= 12) score++
    if (/[A-Z]/.test(pw)) score++
    if (/[0-9]/.test(pw)) score++
    if (/[^A-Za-z0-9]/.test(pw)) score++
    if (score <= 1) return { level: 1, label: 'Weak', color: 'bg-red-400' }
    if (score <= 2) return { level: 2, label: 'Fair', color: 'bg-amber-400' }
    if (score <= 3) return { level: 3, label: 'Good', color: 'bg-blue-400' }
    return { level: 4, label: 'Strong', color: 'bg-emerald-500' }
  }

  const strength = getPasswordStrength(password)

  return (
    <div className="min-h-screen flex bg-[#f8fafc] overflow-hidden font-['Plus_Jakarta_Sans',sans-serif]">
      {/* Left Panel - Immersive Security Portal */}
      <div className="hidden lg:flex lg:w-[480px] xl:w-[600px] flex-col justify-between p-12 text-white relative overflow-hidden shadow-2xl"
        style={{ background: 'linear-gradient(165deg, #020617 0%, #0f172a 60%, #1e293b 100%)' }}>
        
        {/* Animated Background Orbs */}
        <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none">
          <div className="absolute bottom-[-10%] left-[-10%] w-[60%] h-[60%] bg-emerald-500/10 rounded-full blur-[120px] animate-pulse-soft"></div>
          <div className="absolute top-[10%] right-[-10%] w-[50%] h-[50%] bg-sky-500/10 rounded-full blur-[100px]"></div>
          
          {/* Grid Pattern */}
          <div className="absolute inset-0 opacity-[0.03]" 
            style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, white 1px, transparent 0)', backgroundSize: '40px 40px' }}></div>
        </div>

        <div className="relative z-10">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-white/10 flex items-center justify-center text-2xl backdrop-blur-md border border-white/20 shadow-xl">
              <span className="material-symbols-outlined text-emerald-400 font-bold">verified_user</span>
            </div>
            <div>
              <span className="text-2xl font-black tracking-tighter bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">NEEV TIP</span>
              <span className="block text-[10px] text-emerald-400 font-black uppercase tracking-[0.3em] mt-0.5">Onboarding Portal</span>
            </div>
          </div>
        </div>

        <div className="relative z-10 space-y-12">
          <div className="animate-slide-up">
            <h1 className="text-5xl font-extrabold leading-[1.1] tracking-tight">
              Join the<br />
              <span className="text-emerald-400">Elite Defense.</span>
            </h1>
            <p className="mt-6 text-slate-400 text-lg leading-relaxed font-medium">
              Scale your security operations with our enterprise-grade threat intelligence ecosystem.
            </p>
          </div>

          <div className="space-y-6 animate-slide-up" style={{ animationDelay: '0.1s' }}>
            {[
              { icon: '📡', title: 'Intelligence Ecosystem', desc: 'Ingest 1M+ indicators from world-class feeds' },
              { icon: '🔗', title: 'Seamless SIEM Sync', desc: 'Wazuh, Suricata, and Zeek integration ready' },
              { icon: '🔥', title: 'Automated Response', desc: 'Instant firewall blocking and alert routing' },
            ].map(item => (
              <div key={item.title} className="flex items-start gap-4 p-4 rounded-2xl bg-white/5 border border-white/5 hover:bg-white/10 transition-all cursor-default group">
                <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center text-xl shrink-0 group-hover:scale-110 transition-transform duration-300 shadow-inner">{item.icon}</div>
                <div>
                  <div className="font-extrabold text-sm">{item.title}</div>
                  <div className="text-xs font-medium text-slate-400 mt-1 leading-relaxed">{item.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 flex items-center gap-3 text-xs font-bold text-slate-500">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
          Secure Infrastructure Verified
        </div>
      </div>

      {/* Right Panel - Signup Form */}
      <div className="flex-1 flex items-center justify-center p-8 relative">
        <div className="absolute inset-0 opacity-[0.015] pointer-events-none" 
          style={{ backgroundImage: 'linear-gradient(45deg, #0f172a 25%, transparent 25%, transparent 50%, #0f172a 50%, #0f172a 75%, transparent 75%, transparent)', backgroundSize: '60px 60px' }}></div>

        <div className="w-full max-w-[420px] space-y-8 animate-fade-in relative z-10">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="w-12 h-12 rounded-2xl bg-slate-900 flex items-center justify-center text-2xl shadow-xl shadow-slate-900/20">
              <span className="material-symbols-outlined text-emerald-400 font-bold">verified_user</span>
            </div>
            <span className="text-xl font-black text-slate-900 tracking-tighter">NEEV TIP</span>
          </div>

          <div className="text-center lg:text-left">
            <h2 className="text-3xl font-black text-slate-900 tracking-tight">Request Access</h2>
            <p className="text-slate-500 mt-2 font-medium">Join the threat intelligence network</p>
          </div>

          {error && (
            <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-sm text-rose-600 flex items-start gap-3 animate-shake font-bold">
              <span className="material-symbols-outlined text-[20px] mt-0.5">error</span>
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Full Member Name</label>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">person</span>
                <input type="text" value={fullName} onChange={e => setFullName(e.target.value)}
                  className="input pl-12" placeholder="Agent Name" required />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Work Identifier (Email)</label>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">alternate_email</span>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                  className="input pl-12" placeholder="analyst@agency.gov" required />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Account Type</label>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">badge</span>
                <select value={role} onChange={e => setRole(e.target.value)} className="input pl-12 appearance-none" required disabled={optionsLoading}>
                  {(signupOptions.allowed_roles || ['analyst']).map(item => (
                    <option key={item} value={item}>{roleLabels[item] || item}</option>
                  ))}
                </select>
                <span className="material-symbols-outlined absolute right-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 pointer-events-none">expand_more</span>
              </div>
              <p className="text-[10px] font-semibold text-slate-400 ml-1">
                {optionsLoading && 'Loading available roles...'}
                {!optionsLoading && signupOptions.admin_exists && 'Privileged roles are restricted after initial admin setup.'}
                {!optionsLoading && !signupOptions.admin_exists && 'Bootstrap mode: you can create the first admin or SOC manager account.'}
              </p>
            </div>

            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Secure Passphrase</label>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">key</span>
                <input type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  className="input pl-12 pr-12" placeholder="Min 8 characters" required minLength={8} />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors">
                  <span className="material-symbols-outlined text-[20px]">{showPassword ? 'visibility_off' : 'visibility'}</span>
                </button>
              </div>
              {password && (
                <div className="mt-2.5 space-y-2 ml-1">
                  <div className="flex gap-1.5 h-1.5">
                    {[1, 2, 3, 4].map(i => (
                      <div key={i} className={`flex-1 rounded-full transition-all duration-500 ${i <= strength.level ? strength.color : 'bg-slate-100'}`} />
                    ))}
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-[0.1em]">Strength Analysis:</span>
                    <span className={`text-[10px] font-black uppercase tracking-wider ${strength.color === 'bg-emerald-500' ? 'text-emerald-500' : 'text-slate-500'}`}>{strength.label}</span>
                  </div>
                </div>
              )}
            </div>

            <div className="space-y-2">
              <label className="text-[11px] font-black text-slate-500 uppercase tracking-widest ml-1">Verify Passphrase</label>
              <div className="relative group">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-[20px] text-slate-400 group-focus-within:text-sky-500 transition-colors">key</span>
                <input type={showPassword ? 'text' : 'password'} value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
                  className={`input pl-12 ${confirmPassword && confirmPassword !== password ? 'border-rose-300 bg-rose-50/50' : ''}`}
                  placeholder="Repeat passphrase" required />
              </div>
            </div>

            <div className="flex items-start gap-3 p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <input type="checkbox" id="terms" required className="mt-1 w-4 h-4 rounded border-slate-300 accent-sky-500" />
              <label htmlFor="terms" className="text-[11px] text-slate-500 font-bold leading-relaxed uppercase tracking-tight">
                I hereby acknowledge the <span className="text-sky-600 hover:underline cursor-pointer">Operational protocols</span> and <span className="text-sky-600 hover:underline cursor-pointer">Security Compliance</span> standards.
              </label>
            </div>

            <button type="submit" disabled={loading || (confirmPassword && confirmPassword !== password)}
              className="btn btn-primary w-full py-4 text-base font-black uppercase tracking-widest group bg-slate-900 border-2 border-slate-900 hover:bg-emerald-600 hover:border-emerald-600 shadow-2xl shadow-slate-900/10 hover:shadow-emerald-500/30 relative overflow-hidden transition-all duration-300 mt-4 disabled:opacity-30">
              <span className="relative z-10 flex items-center justify-center gap-3">
                {loading ? (
                  <>
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                    Processing...
                  </>
                ) : (
                  <>
                    Establish Identity
                    <span className="material-symbols-outlined group-hover:translate-x-1 transition-transform">person_add</span>
                  </>
                )}
              </span>
            </button>
          </form>

          <p className="text-center text-sm font-bold text-slate-500">
            Already registered?{' '}
            <button onClick={onSwitchToLogin} className="text-sky-600 hover:underline font-black">Begin Session</button>
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
