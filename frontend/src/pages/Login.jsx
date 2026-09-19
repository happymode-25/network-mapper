import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, login, apiErrorMessage } from '../api'

export default function Login() {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await login(username, password)
      navigate('/')
    } catch (err) {
      setError(apiErrorMessage(err, 'Login failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={onSubmit} className="w-full max-w-sm rounded-lg bg-slate-900 border border-slate-800 p-6 shadow-xl">
        <h1 className="text-xl font-bold mb-1">Network Mapper</h1>
        <p className="text-sm text-slate-400 mb-6">Sign in to the discovery &amp; assessment platform</p>
        <label className="block text-sm text-slate-300 mb-1">Username</label>
        <input
          className="w-full rounded border border-slate-700 bg-slate-800 px-3 py-2 mb-4"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <label className="block text-sm text-slate-300 mb-1">Password</label>
        <input
          type="password"
          className="w-full rounded border border-slate-700 bg-slate-800 px-3 py-2 mb-4"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-3 py-2 font-semibold"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="text-xs text-slate-500 mt-4">
          Default credentials are configured via DEFAULT_ADMIN_USERNAME / DEFAULT_ADMIN_PASSWORD.
        </p>
      </form>
    </div>
  )
}