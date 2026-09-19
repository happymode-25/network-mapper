import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import Layout, { Loading, ErrorBox, SeverityBadge } from '../components/Layout'
import { formatScore } from '../theme'
import { useState } from 'react'

function DiffSection({ title, color, items, empty }) {
  return (
    <section className="rounded-lg bg-slate-900 border border-slate-800 p-4">
      <h3 className="font-semibold mb-3" style={{ color }}>{title} ({items.length})</h3>
      {items.length ? (
        <table className="w-full text-sm">
          <thead className="text-slate-400 text-left">
            <tr>
              <th className="pb-2">CVE</th>
              <th className="pb-2">Severity</th>
              <th className="pb-2">Risk</th>
              <th className="pb-2">Confidence</th>
              <th className="pb-2">Service</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {items.map((item) => (
              <tr key={item.cve_id}>
                <td className="py-2 font-mono text-blue-300">{item.cve_id}</td>
                <td className="py-2"><SeverityBadge severity={item.severity} /></td>
                <td className="py-2">{formatScore(item.risk_score)}</td>
                <td className="py-2 capitalize">{item.confidence}</td>
                <td className="py-2">
                  {item.service}{item.version ? ` ${item.version}` : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-sm text-slate-500">{empty}</p>
      )}
    </section>
  )
}

export default function Compare() {
  const [scanA, setScanA] = useState('')
  const [scanB, setScanB] = useState('')
  const scansQ = useQuery({ queryKey: ['scans'], queryFn: () => api.get('/scans?size=100').then((r) => r.data) })
  const completed = (scansQ.data?.items || []).filter((s) => s.status === 'completed')
  const diffQ = useQuery({
    queryKey: ['compare', scanA, scanB],
    queryFn: () => api.get(`/compare?scan_a=${scanA}&scan_b=${scanB}`).then((r) => r.data),
    enabled: Boolean(scanA && scanB && scanA !== scanB),
  })

  return (
    <Layout>
      <h2 className="text-2xl font-bold mb-6">Compare scans</h2>

      <div className="mb-8 flex items-end gap-3">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Baseline (scan A)</label>
          <select value={scanA} onChange={(e) => setScanA(e.target.value)} className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm">
            <option value="">Select…</option>
            {completed.map((s) => <option key={s.id} value={s.id}>Scan #{s.id}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Compared (scan B)</label>
          <select value={scanB} onChange={(e) => setScanB(e.target.value)} className="rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm">
            <option value="">Select…</option>
            {completed.map((s) => <option key={s.id} value={s.id}>Scan #{s.id}</option>)}
          </select>
        </div>
      </div>

      {!scanA || !scanB || scanA === scanB ? (
        <p className="text-sm text-slate-400">Select two completed scans to diff their findings.</p>
      ) : diffQ.isLoading ? (
        <Loading />
      ) : diffQ.isError ? (
        <ErrorBox message="Failed to compare scans" />
      ) : (
        <div className="grid grid-cols-3 gap-6">
          <DiffSection title="Added in B" color="#E76F51" items={diffQ.data.added} empty="Nothing new" />
          <DiffSection title="Removed from B" color="#2A9D8F" items={diffQ.data.removed} empty="Nothing removed" />
          <DiffSection title="Changed" color="#E9C46A" items={diffQ.data.changed} empty="Nothing changed" />
        </div>
      )}
    </Layout>
  )
}