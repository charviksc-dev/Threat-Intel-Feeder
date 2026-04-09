import { useState, useEffect } from 'react'

export default function AdminPanel({ axiosClient }) {
  const [users, setUsers] = useState([])
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [newUser, setNewUser] = useState({ email: '', password: '', full_name: '', role: 'analyst' })
  const [result, setResult] = useState(null)

  useEffect(() => { loadData() }, [])

  async function loadData() {
    setLoading(true)
    try {
      const usersRes = await axiosClient.get('/admin/users').catch(e => e.response?.status === 403 ? { data: [], error: 'access_denied' } : { data: [] })
      const healthRes = await axiosClient.get('/admin/system-health').catch(e => e.response?.status === 403 ? { data: null, error: 'access_denied' } : { data: null })
      
      setUsers(usersRes.data || [])
      setHealth(healthRes.data || (usersRes.error === 'access_denied' ? { access_denied: true } : null))
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  async function createUser() {
    try {
      await axiosClient.post('/admin/users', null, { params: newUser })
      setResult({ type: 'success', message: 'User created' })
      setShowCreateUser(false)
      setNewUser({ email: '', password: '', full_name: '', role: 'analyst' })
      loadData()
    } catch (err) {
      setResult({ type: 'error', message: err.response?.data?.detail || 'Failed' })
    }
    setTimeout(() => setResult(null), 5000)
  }

  async function changeRole(userId, role) {
    try {
      await axiosClient.put(`/admin/users/${userId}/role`, null, { params: { role } })
      setResult({ type: 'success', message: 'Role updated' })
      loadData()
    } catch (err) {
      setResult({ type: 'error', message: 'Failed to update role' })
    }
  }

  async function deactivateUser(userId) {
    try {
      await axiosClient.put(`/admin/users/${userId}/deactivate`)
      setResult({ type: 'success', message: 'User deactivated' })
      loadData()
    } catch (err) {
      setResult({ type: 'error', message: 'Failed' })
    }
  }

  const roleColors = {
    admin: 'bg-red-100 text-red-700 border-red-200',
    analyst: 'bg-blue-100 text-blue-700 border-blue-200',
    viewer: 'bg-slate-100 text-slate-600 border-slate-200',
  }

  if (loading) {
    return <div className="card text-center py-8"><div className="inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin"></div></div>
  }

  if (health?.access_denied) {
    return (
      <div className="flex flex-col items-center justify-center py-20 bg-white rounded-3xl border border-rose-100 shadow-sm">
        <div className="w-20 h-20 rounded-full bg-rose-50 flex items-center justify-center mb-6 border border-rose-100 shadow-inner">
          <span className="material-symbols-outlined text-4xl text-rose-500">lock</span>
        </div>
        <h2 className="text-lg font-bold text-slate-900">Access Denied</h2>
        <p className="text-sm text-slate-500 mt-2 max-w-md text-center">
          You are currently logged in with the <strong>Analyst</strong> role. 
          Administrator privileges are required to view system health, manage users, and audit platform activity.
        </p>
        <div className="mt-8 p-4 bg-slate-50 rounded-2xl border border-slate-100 text-xs text-slate-400 font-mono">
          Required Role: <span className="text-rose-500">admin</span>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {result && (
        <div className={`p-4 rounded-2xl text-sm font-bold shadow-sm animate-slide-up ${result.type === 'success' ? 'bg-emerald-50 border border-emerald-200 text-emerald-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined">{result.type === 'success' ? 'check_circle' : 'error'}</span>
            {result.message}
          </div>
        </div>
      )}

      {/* System Health */}
      <div className="card shadow-md">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-xl bg-sky-50 text-sky-500">
            <span className="material-symbols-outlined">health_metrics</span>
          </div>
          <div>
            <h3 className="text-base font-black tracking-tight text-slate-800">System Vital Monitoring</h3>
            <p className="text-[10px] uppercase font-black tracking-widest text-slate-400">Real-time Backend Status</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {health?.services && Object.entries(health.services).map(([service, info]) => (
            <div key={service} className="p-4 rounded-2xl bg-slate-50/50 border border-slate-100 hover:border-sky-100 hover:bg-white transition-all group">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-black uppercase tracking-widest text-slate-600">{service}</span>
                <div className={`w-2 h-2 rounded-full ${info.status === 'up' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)] animate-pulse' : 'bg-red-500'}`}></div>
              </div>
              <div className="flex items-center gap-2">
                 <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-lg ${info.status === 'up' ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'}`}>
                   {info.status === 'up' ? 'Operational' : 'Critical Failure'}
                 </span>
              </div>
              {info.version && <div className="text-[10px] font-bold text-slate-400 mt-3 group-hover:text-sky-500 transition-colors">v{info.version}</div>}
              {info.error && <p className="text-[9px] text-rose-400 mt-2 font-mono break-all leading-tight">{info.error}</p>}
            </div>
          ))}
        </div>
        <div className="mt-6 flex items-center justify-between pt-4 border-t border-slate-100">
          <div className="text-[10px] font-black uppercase tracking-widest text-slate-400">Platform Synchronized</div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Aggregate State:</span>
            <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-lg ${health?.status === 'healthy' ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/20' : 'bg-amber-500 text-white shadow-lg shadow-amber-500/20'}`}>
              {health?.status || 'Unknown'}
            </span>
          </div>
        </div>
      </div>

      {/* User Management */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold">User Management</h3>
            <p className="text-xs text-slate-400">{users.length} users</p>
          </div>
          <button onClick={() => setShowCreateUser(!showCreateUser)} className="btn btn-primary text-sm">
            + Add User
          </button>
        </div>

        {/* Create User Form */}
        {showCreateUser && (
          <div className="mb-4 p-4 rounded-xl bg-slate-50 border border-slate-200 animate-fade-in">
            <h4 className="text-sm font-semibold mb-3">Create New User</h4>
            <div className="grid md:grid-cols-2 gap-3">
              <input type="text" placeholder="Full name" value={newUser.full_name}
                onChange={e => setNewUser({...newUser, full_name: e.target.value})} className="input py-2" />
              <input type="email" placeholder="Email" value={newUser.email}
                onChange={e => setNewUser({...newUser, email: e.target.value})} className="input py-2" />
              <input type="password" placeholder="Password (min 8 chars)" value={newUser.password}
                onChange={e => setNewUser({...newUser, password: e.target.value})} className="input py-2" />
              <select value={newUser.role} onChange={e => setNewUser({...newUser, role: e.target.value})} className="input py-2">
                <option value="viewer">Viewer (read-only)</option>
                <option value="analyst">Analyst (standard)</option>
                <option value="admin">Admin (full access)</option>
              </select>
            </div>
            <div className="flex gap-2 mt-3">
              <button onClick={createUser} className="btn btn-primary text-sm">Create User</button>
              <button onClick={() => setShowCreateUser(false)} className="btn btn-ghost text-sm">Cancel</button>
            </div>
          </div>
        )}

        {/* Users Table */}
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="table-header">
                <th className="px-4 py-3 rounded-l-lg">User</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Provider</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Last Login</th>
                <th className="px-4 py-3 rounded-r-lg">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="table-row">
                  <td className="px-4 py-3">
                    <div>
                      <div className="text-sm font-medium">{user.full_name || '—'}</div>
                      <div className="text-xs text-slate-400">{user.email}</div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <select value={user.role} onChange={e => changeRole(user.id, e.target.value)}
                      className={`text-xs font-semibold px-2 py-1 rounded-lg border ${roleColors[user.role]}`}>
                      <option value="viewer">Viewer</option>
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    <span className="badge badge-neutral">{user.provider || 'local'}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`badge ${user.is_active ? 'badge-success' : 'badge-danger'}`}>
                      {user.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    {user.is_active && (
                      <button onClick={() => deactivateUser(user.id)} className="text-xs text-red-500 hover:underline">
                        Deactivate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Role Permissions */}
      <div className="card">
        <h3 className="text-base font-semibold mb-4">Role Permissions</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="table-header">
                <th className="px-4 py-3 rounded-l-lg">Permission</th>
                <th className="px-4 py-3 text-center">Viewer</th>
                <th className="px-4 py-3 text-center">Analyst</th>
                <th className="px-4 py-3 text-center rounded-r-lg">Admin</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['View indicators', '✅', '✅', '✅'],
                ['Search & filter', '✅', '✅', '✅'],
                ['Export data', '❌', '✅', '✅'],
                ['Enrich indicators', '❌', '✅', '✅'],
                ['Bulk operations', '❌', '✅', '✅'],
                ['Trigger feed sync', '❌', '✅', '✅'],
                ['Manage users', '❌', '❌', '✅'],
                ['System health', '❌', '❌', '✅'],
                ['Audit logs', '❌', '❌', '✅'],
              ].map(([perm, viewer, analyst, admin]) => (
                <tr key={perm} className="table-row">
                  <td className="px-4 py-2.5 font-medium">{perm}</td>
                  <td className="px-4 py-2.5 text-center">{viewer}</td>
                  <td className="px-4 py-2.5 text-center">{analyst}</td>
                  <td className="px-4 py-2.5 text-center">{admin}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
