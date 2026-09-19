import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, apiErrorMessage } from '../api'
import Layout, { Loading, ErrorBox } from '../components/Layout'
import { formatTime } from '../theme'

const allowlist = (import.meta.env.VITE_ALLOWED_TARGETS || '127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12')

export default function Targets() {
  const [ip, setIp] = useState('')
  const [hostname, setHostname] = useState('')
  const [error, setError] = useState('')
  const queryClient = useQueryClient()

  const q = useQuery({ queryKey: ['targets'], queryFn: () => api.get('/targets?size=100').then((r) => r.data) })

  const create = useMutation({
    mutationFn: () => api.post('/targets', { ip, hostname: hostname || null }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      setIp('')
      setHostname('')
      setError('')
    },
    onError: (err) => setError(apiErrorMessage(err, 'Failed to add target')),
  })

  return (
    <Layout>
      <h2 className="text-2xl font-bold mb-2">Targets</h2>
      <p className="text-sm text-slate-400 mb-6">
        Allowlist: <code className="text-slate-300">{allowlist}</code>. Targets outside of it are rejected.
      </p>

      <div className="mb-8 rounded-lg bg-slate-900 border border-slate-800 p-4 flex items-end gap-3 flex-wrap">
        <div>
          <label className="block text-xs text-slate-400 mb-1">IP address</label>
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.42" className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm" />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Hostname</label>
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="db-prod-01" className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm" />
        </div>
        <button
          onClick={() => create.mutate()}
          disabled={!ip || create.isPending}
          className="rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2 text-sm font-semibold"
        >
          {create.isPending ? 'Adding…' : 'Add target'}
        </button>
        {error && <div className="text-sm text-red-400">{error}</div>}
      </div>

      {q.isLoading ? <Loading /> : q.isError ? <ErrorBox message="Failed to load targets" /> : (
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <table className="w-full text-sm">
            <thead className="text-slate-400 text-left">
              <tr>
                <th className="pb-2">ID</th>
                <th className="pb-2">IP</th>
                <th className="pb-2">Hostname</th>
                <th className="pb-2">Authorized</th>
                <th className="pb-2">Added</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {(q.data?.items || []).map((t) => (
                <tr key={t.id}>
                  <td className="py-2 font-mono">{t.id}</td>
                  <td className="py-2 font-mono">{t.ip}</td>
                  <td className="py-2">{t.hostname || '—'}</td>
                  <td className="py-2">
                    {t.authorized ? <span className="text-emerald-400">yes</span> : <span className="text-red-400">no</span>}
                  </td>
                  <td className="py-2">{formatTime(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Layout>
  )
}