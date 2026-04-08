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
      const [usersRes, healthRes] = await Promise.all([
        axiosClient.get('/admin/users'),
        axiosClient.get('/admin/system-health'),
      ])
      setUsers(usersRes.data)
      setHealth(healthRes.data)
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

  return (
    <div className="space-y-6">
      {result && (
        <div className={`p-3 rounded-xl text-sm ${result.type === 'success' ? 'bg-emerald-50 border border-emerald-200 text-emerald-700' : 'bg-red-50 border border-red-200 text-red-700'}`}>
          {result.message}
        </div>
      )}

      {/* System Health */}
      <div className="card">
        <h3 className="text-base font-semibold mb-4">System Health</h3>
        <div className="grid grid-cols-3 gap-4">
          {Object.entries(health?.services || {}).map(([service, info]) => (
            <div key={service} className="p-4 rounded-xl bg-slate-50 border border-slate-100">
              <div className="flex items-center gap-2 mb-2">
                <div className={`w-2.5 h-2.5 rounded-full ${info.status === 'up' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></div>
                <span className="text-sm font-semibold capitalize">{service}</span>
              </div>
              <div className="text-xs text-slate-500">
                {info.status === 'up' ? 'Operational' : `Error: ${info.error?.substring(0, 50)}`}
              </div>
              {info.version && <div className="text-[10px] text-slate-400 mt-1">v{info.version}</div>}
            </div>
          ))}
        </div>
        <div className="mt-3 text-xs text-slate-400">
          Overall status: <span className={`font-semibold ${health?.status === 'healthy' ? 'text-emerald-600' : 'text-amber-600'}`}>{health?.status}</span>
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
