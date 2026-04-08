import { useEffect, useState } from 'react'

export default function OAuthCallback({ provider, onLogin }) {
  const [error, setError] = useState('')
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')

    if (!code) {
      setError('No authorization code received')
      return
    }

    async function exchangeCode() {
      try {
        const res = await fetch(`${apiUrl}/auth/oauth/${provider}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, provider }),
        })

        if (!res.ok) {
          const data = await res.json()
          throw new Error(data.detail || 'OAuth authentication failed')
        }

        const data = await res.json()
        onLogin(data.access_token, data.user)
      } catch (err) {
        setError(err.message)
      }
    }

    exchangeCode()
  }, [provider])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-surface">
        <div className="text-center max-w-md">
          <div className="text-4xl mb-4">⚠️</div>
          <h2 className="text-xl font-bold text-primary mb-2">Authentication Failed</h2>
          <p className="text-slate-500 mb-4">{error}</p>
          <a
            href="/"
            className="inline-block bg-primary text-white px-6 py-3 rounded-xl text-sm font-medium hover:bg-slate-900"
          >
            Back to Login
          </a>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface">
      <div className="text-center">
        <div className="inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4"></div>
        <p className="text-slate-500">Authenticating with {provider}...</p>
      </div>
    </div>
  )
}
