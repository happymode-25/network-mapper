import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import Layout, { StatCard, Loading, ErrorBox, StatusBadge, SeverityDot } from '../components/Layout'
import { formatTime, severityColor, formatPortNumber } from '../theme'

function severitySummary(scan) {
  const counts = { none: 0, low: 0, medium: 0, high: 0, critical: 0 }
  const severityOrder = ['none', 'low', 'medium', 'high', 'critical']
  for (const f of scan.findings || []) {
    const key = (f.severity || 'none').toLowerCase()
    if (key in counts) counts[key] += 1
  }
  return { counts, order: severityOrder }
}

export default function Dashboard() {
  const scansQ = useQuery({ queryKey: ['scans'], queryFn: () => api.get('/scans?size=10').then((r) => r.data) })
  const targetsQ = useQuery({ queryKey: ['targets'], queryFn: () => api.get('/targets?size=100').then((r) => r.data) })
  const lastScan = scansQ.data?.items?.find((s) => s.status === 'completed')
  const targetMap = Object.fromEntries((targetsQ.data?.items || []).map((t) => [t.id, t.ip]))
  const detailQ = useQuery({
    queryKey: ['scan', lastScan?.id],
    queryFn: () => api.get(`/scans/${lastScan.id}`).then((r) => r.data),
    enabled: Boolean(lastScan),
  })

  if (scansQ.isLoading || targetsQ.isLoading) return <Layout><Loading /></Layout>
  if (scansQ.isError) return <Layout><ErrorBox message="Failed to load scans" /></Layout>

  const summary = detailQ.data ? severitySummary(detailQ.data) : null
  const findings = detailQ.data?.findings || []

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Dashboard</h2>
        <a href="/targets" className="text-sm text-blue-400 hover:underline">Add a target</a>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-8">
        <StatCard label="Targets" value={targetsQ.data?.total ?? 0} />
        <StatCard label="Scans run" value={scansQ.data?.total ?? 0} />
        <StatCard label="Completed" value={scansQ.data?.items?.filter((s) => s.status === 'completed').length ?? 0} />
        <StatCard label="High+ findings (last scan)" value={findings.filter((f) => ['high', 'critical'].includes(f.severity)).length} color="#E76F51" />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <section className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <h3 className="font-semibold mb-3">Severity summary — scan #{lastScan?.id || '—'}</h3>
          {summary ? (
            <div className="flex gap-4">
              {summary.order.map((sev) => (
                <div key={sev} className="flex items-center gap-2">
                  <SeverityDot severity={sev} />
                  <span className="text-sm capitalize">{sev}</span>
                  <span className="text-sm font-bold" style={{ color: severityColor(sev) }}>
                    {summary.counts[sev]}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500">Run a scan to populate severity statistics.</p>
          )}
        </section>

        <section className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <h3 className="font-semibold mb-3">Services on last scan</h3>
          {detailQ.data?.ports?.length ? (
            <div className="flex flex-wrap gap-2">
              {detailQ.data.ports.map((p) => (
                <span key={p.id} className="rounded bg-slate-800 px-2 py-1 text-xs font-mono">
                  {formatPortNumber(p.port)}
                  {p.service?.product && ` · ${p.service.product}${p.service.version ? ` ${p.service.version}` : ''}`}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500">No open ports detected yet.</p>
          )}
        </section>
      </div>

      <section className="mt-8 rounded-lg bg-slate-900 border border-slate-800 p-4">
        <h3 className="font-semibold mb-3">Recent scans</h3>
        <table className="w-full text-sm">
          <thead className="text-slate-400 text-left">
            <tr>
              <th className="pb-2">ID</th>
              <th className="pb-2">Target</th>
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
                <td className="py-2">{targetMap[s.target_id] || s.target_id}</td>
                <td className="py-2"><StatusBadge status={s.status} /></td>
                <td className="py-2">{formatTime(s.started_at)}</td>
                <td className="py-2">{formatTime(s.finished_at)}</td>
                <td className="py-2">
                  <a href={`/scans/${s.id}`} className="text-blue-400 hover:underline">View</a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </Layout>
  )
}