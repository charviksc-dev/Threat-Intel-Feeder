import { useState } from 'react'

export default function SignupPage({ onSignup, onSwitchToLogin }) {
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

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
        body: JSON.stringify({ email, password, full_name: fullName }),
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
    <div className="min-h-screen flex">
      {/* Left Panel */}
      <div className="hidden lg:flex lg:w-[480px] xl:w-[560px] flex-col justify-between p-12 text-white relative overflow-hidden"
        style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 40%, #0f172a 100%)' }}>
        <div className="absolute top-0 left-0 w-full h-full opacity-5">
          <div className="absolute top-40 right-20 w-80 h-80 bg-emerald-500 rounded-full blur-[120px]"></div>
          <div className="absolute bottom-40 left-10 w-72 h-72 bg-blue-500 rounded-full blur-[100px]"></div>
        </div>

        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center text-xl backdrop-blur-sm border border-white/10">🛡️</div>
            <div>
              <span className="text-lg font-bold tracking-tight">Neev TIP</span>
              <span className="block text-[10px] text-slate-400 uppercase tracking-widest">Threat Intelligence</span>
            </div>
          </div>
        </div>

        <div className="relative z-10 space-y-6">
          <div>
            <h1 className="text-4xl font-bold leading-tight tracking-tight">Join your<br />SOC team</h1>
            <p className="mt-4 text-slate-400 leading-relaxed">
              Get access to centralized threat intelligence, SIEM integrations, and automated blocking capabilities.
            </p>
          </div>

          <div className="space-y-4">
            {[
              { icon: '📡', title: '8 Threat Feeds', desc: 'URLhaus, ThreatFox, Feodo, Emerging Threats, OTX, VT, MISP' },
              { icon: '🔗', title: '9 SIEM Integrations', desc: 'Wazuh, Suricata, Zeek, TheHive, Cortex, Firewall' },
              { icon: '🔥', title: 'Auto Block', desc: 'iptables, pf, nftables, DNS sinkhole exports' },
            ].map(item => (
              <div key={item.title} className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-white/10 flex items-center justify-center text-base shrink-0 mt-0.5">{item.icon}</div>
                <div>
                  <div className="font-semibold text-sm">{item.title}</div>
                  <div className="text-xs text-slate-400 mt-0.5">{item.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 text-xs text-slate-500">Enterprise-grade threat intelligence</div>
      </div>

      {/* Right Panel - Signup Form */}
      <div className="flex-1 flex items-center justify-center p-8 bg-surface">
        <div className="w-full max-w-[400px] animate-fade-in">
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center text-xl">🛡️</div>
            <span className="text-xl font-bold text-primary">Neev TIP</span>
          </div>

          <div className="mb-8">
            <h2 className="text-2xl font-bold text-primary tracking-tight">Create your account</h2>
            <p className="text-slate-500 mt-1.5">Get started with your SOC dashboard</p>
          </div>

          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-red-50 border border-red-200 text-sm text-red-700 flex items-start gap-2">
              <svg className="w-4 h-4 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" /></svg>
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Full name</label>
              <input type="text" value={fullName} onChange={e => setFullName(e.target.value)}
                className="input" placeholder="John Doe" required />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Work email</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                className="input" placeholder="analyst@company.com" required />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
              <div className="relative">
                <input type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  className="input pr-12" placeholder="Min 8 characters" required minLength={8} />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-slate-600 font-medium">
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              {password && (
                <div className="mt-2.5 flex items-center gap-2">
                  <div className="flex gap-1 flex-1">
                    {[1, 2, 3, 4].map(i => (
                      <div key={i} className={`h-1.5 flex-1 rounded-full transition-all duration-300 ${i <= strength.level ? strength.color : 'bg-slate-200'}`} />
                    ))}
                  </div>
                  <span className="text-[11px] text-slate-500 font-medium w-12 text-right">{strength.label}</span>
                </div>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Confirm password</label>
              <input type={showPassword ? 'text' : 'password'} value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
                className={`input ${confirmPassword && confirmPassword !== password ? 'border-red-300 bg-red-50/50 focus:ring-red-200 focus:border-red-400' : ''}`}
                placeholder="Re-enter your password" required />
              {confirmPassword && confirmPassword !== password && (
                <p className="mt-1.5 text-xs text-red-500 flex items-center gap-1">
                  <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>
                  Passwords do not match
                </p>
              )}
            </div>

            <div className="flex items-start gap-2.5 pt-1">
              <input type="checkbox" id="terms" required className="mt-1 rounded border-slate-300 accent-accent" />
              <label htmlFor="terms" className="text-xs text-slate-500 leading-relaxed">
                I agree to the <span className="text-accent hover:underline cursor-pointer font-medium">Terms of Service</span> and <span className="text-accent hover:underline cursor-pointer font-medium">Privacy Policy</span>
              </label>
            </div>

            <button type="submit" disabled={loading || (confirmPassword && confirmPassword !== password)}
              className="btn btn-primary w-full py-3.5 text-[15px] mt-2">
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
                  Creating account...
                </span>
              ) : 'Create account'}
            </button>
          </form>

          <p className="mt-8 text-center text-sm text-slate-500">
            Already have an account?{' '}
            <button onClick={onSwitchToLogin} className="text-accent font-semibold hover:underline">Sign in</button>
          </p>
        </div>
      </div>
    </div>
  )
}
