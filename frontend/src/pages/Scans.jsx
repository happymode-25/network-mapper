import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, apiErrorMessage } from '../api'
import Layout, { StatusBadge } from '../components/Layout'
import { formatTime } from '../theme'

export default function Scans() {
  const [targetId, setTargetId] = useState('')
  const [ports, setPorts] = useState('')
  const [error, setError] = useState('')
  const queryClient = useQueryClient()

  const scansQ = useQuery({ queryKey: ['scans'], queryFn: () => api.get('/scans?size=50').then((r) => r.data) })
  const targetsQ = useQuery({ queryKey: ['targets'], queryFn: () => api.get('/targets?size=100').then((r) => r.data) })

  const startScan = useMutation({
    mutationFn: () => api.post('/scans', { target_id: Number(targetId), ports_to_scan: ports.trim() || null }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setTargetId('')
      setPorts('')
      setError('')
    },
    onError: (err) => setError(apiErrorMessage(err, 'Failed to start scan')),
  })

  return (
    <Layout>
      <h2 className="text-2xl font-bold mb-6">Scans</h2>

      <div className="mb-8 rounded-lg bg-slate-900 border border-slate-800 p-4 flex items-end gap-3">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Target</label>
          <select
            className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
          >
            <option value="">Select a target…</option>
            {(targetsQ.data?.items || []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.ip}{t.hostname ? ` (${t.hostname})` : ''} {t.authorized ? '' : '— not authorized'}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Ports (optional)</label>
          <input
            className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm w-56"
            placeholder="e.g. 22,80-82,443"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
          />
        </div>
        <button
          onClick={() => startScan.mutate()}
          disabled={!targetId || startScan.isPending}
          className="rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2 text-sm font-semibold"
        >
          {startScan.isPending ? 'Queuing…' : 'Run scan'}
        </button>
        {error && <div className="text-sm text-red-400 mb-1">{error}</div>}
      </div>

      <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
        <table className="w-full text-sm">
          <thead className="text-slate-400 text-left">
            <tr>
              <th className="pb-2">ID</th>
              <th className="pb-2">Target</th>
              <th className="pb-2">Ports</th>
              <th className="pb-2">Status</th>
              <th className="pb-2">Started</th>
              <th className="pb-2">Finished</th>
              <th className="pb-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {(scansQ.data?.items || []).map((s) => (
              <tr key={s.id}>
                <td className="py-2 font-mono">{s.id}</td>
                <td className="py-2">{s.target_id}</td>
                <td className="py-2 text-xs text-slate-400">{s.requested_ports || 'default'}</td>
                <td className="py-2"><StatusBadge status={s.status} /></td>
                <td className="py-2">{formatTime(s.started_at)}</td>
                <td className="py-2">{formatTime(s.finished_at)}</td>
                <td className="py-2">
                  <Link to={`/scans/${s.id}`} className="text-blue-400 hover:underline">Details</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  )
}