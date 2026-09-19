import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import Layout, { Loading, ErrorBox } from '../components/Layout'

const IMPORTANCE = ['none', 'low', 'medium', 'high', 'critical']

export default function Assets() {
  const [showForm, setShowForm] = useState(false)
  const [newAsset, setNewAsset] = useState({ ip: '', hostname: '', importance: 'low', owner: '', tags: '' })
  const queryClient = useQueryClient()

  const q = useQuery({ queryKey: ['assets'], queryFn: () => api.get('/assets?size=100').then((r) => r.data) })

  const update = useMutation({
    mutationFn: ({ id, importance }) => api.put(`/assets/${id}`, { importance }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['assets'] }),
  })

  const create = useMutation({
    mutationFn: () => api.post('/assets', newAsset),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] })
      setNewAsset({ ip: '', hostname: '', importance: 'low', owner: '', tags: '' })
      setShowForm(false)
    },
  })

  function toggle(id, importance) {
    const next = IMPORTANCE[(IMPORTANCE.indexOf(importance) + 1) % IMPORTANCE.length]
    update.mutate({ id, importance: next })
  }

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Assets</h2>
        <button onClick={() => setShowForm((v) => !v)} className="rounded bg-blue-600 hover:bg-blue-500 px-4 py-2 text-sm font-semibold">
          {showForm ? 'Cancel' : 'New asset'}
        </button>
      </div>

      {showForm && (
        <form
          onSubmit={(e) => { e.preventDefault(); create.mutate() }}
          className="mb-8 rounded-lg bg-slate-900 border border-slate-800 p-4 grid grid-cols-5 gap-3 items-end"
        >
          <div>
            <label className="block text-xs text-slate-400 mb-1">IP</label>
            <input value={newAsset.ip} onChange={(e) => setNewAsset({ ...newAsset, ip: e.target.value })} className="rounded border border-slate-700 bg-slate-800 px-2 py-2 w-full text-sm" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Hostname</label>
            <input value={newAsset.hostname} onChange={(e) => setNewAsset({ ...newAsset, hostname: e.target.value })} className="rounded border border-slate-700 bg-slate-800 px-2 py-2 w-full text-sm" />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Importance</label>
            <select value={newAsset.importance} onChange={(e) => setNewAsset({ ...newAsset, importance: e.target.value })} className="rounded border border-slate-700 bg-slate-800 px-2 py-2 w-full text-sm">
              {IMPORTANCE.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Owner</label>
            <input value={newAsset.owner} onChange={(e) => setNewAsset({ ...newAsset, owner: e.target.value })} className="rounded border border-slate-700 bg-slate-800 px-2 py-2 w-full text-sm" />
          </div>
          <button type="submit" className="rounded bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-sm font-semibold">
            Save
          </button>
        </form>
      )}

      {q.isLoading ? <Loading /> : q.isError ? <ErrorBox message="Failed to load assets" /> : (
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <p className="text-xs text-slate-500 mb-3">Click an importance badge to cycle its value — importance feeds the risk score.</p>
          <table className="w-full text-sm">
            <thead className="text-slate-400 text-left">
              <tr>
                <th className="pb-2">ID</th>
                <th className="pb-2">IP</th>
                <th className="pb-2">Hostname</th>
                <th className="pb-2">Importance</th>
                <th className="pb-2">Owner</th>
                <th className="pb-2">Tags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {(q.data?.items || []).map((a) => (
                <tr key={a.id}>
                  <td className="py-2 font-mono">{a.id}</td>
                  <td className="py-2 font-mono">{a.ip || '—'}</td>
                  <td className="py-2">{a.hostname || '—'}</td>
                  <td className="py-2">
                    <button onClick={() => toggle(a.id, a.importance)} className="rounded-full px-2.5 py-0.5 text-xs font-semibold bg-slate-800 hover:bg-slate-700 capitalize">
                      {a.importance}
                    </button>
                  </td>
                  <td className="py-2">{a.owner || '—'}</td>
                  <td className="py-2">{a.tags || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Layout>
  )
}