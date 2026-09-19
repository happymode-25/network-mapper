import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { api } from '../api'
import Layout, { Loading, ErrorBox, StatusBadge, SeverityBadge } from '../components/Layout'
import FindingTable from '../components/FindingTable'
import { formatPortNumber, formatScore } from '../theme'

export default function ScanDetail() {
  const { id } = useParams()
  const q = useQuery({ queryKey: ['scan', id], queryFn: () => api.get(`/scans/${id}`).then((r) => r.data) })
  const exportFormats = [
    { key: 'json', label: 'JSON' },
    { key: 'csv', label: 'CSV' },
    { key: 'stix', label: 'STIX 2.1' },
  ]
  const downloadExport = (fmt) => {
    api.get(`/scans/${id}/export?format=${fmt}`, { responseType: 'blob' }).then((r) => {
      const url = URL.createObjectURL(r.data)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan-${id}.${fmt === 'json' || fmt === 'stix' ? 'json' : 'csv'}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    })
  }

  if (q.isLoading) return <Layout><Loading /></Layout>
  if (q.isError) return <Layout><ErrorBox message="Failed to load scan" /></Layout>
  const scan = q.data

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Scan #{scan.id}</h2>
        <div className="flex items-center gap-2">
          {exportFormats.map((f) => (
            <button
              key={f.key}
              onClick={() => downloadExport(f.key)}
              className="rounded border border-slate-600 px-3 py-1 text-xs hover:bg-slate-800"
            >
              Export {f.label}
            </button>
          ))}
          <StatusBadge status={scan.status} />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6 text-sm">
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <div className="text-slate-400 text-xs">Target</div>
          <div className="font-mono mt-1">{scan.target.ip}</div>
          {scan.target.hostname && <div className="text-slate-500 text-xs">{scan.target.hostname}</div>}
        </div>
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <div className="text-slate-400 text-xs">Started</div>
          <div className="mt-1">{scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}</div>
        </div>
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <div className="text-slate-400 text-xs">Finished</div>
          <div className="mt-1">{scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '—'}</div>
        </div>
        <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
          <div className="text-slate-400 text-xs">Findings</div>
          <div className="mt-1 font-bold">{scan.findings.length}</div>
        </div>
      </div>

      {scan.error && <div className="mb-6 rounded bg-red-900/40 border border-red-700 p-3 text-sm text-red-200">{scan.error}</div>}

      <section className="mb-8 rounded-lg bg-slate-900 border border-slate-800 p-4">
        <h3 className="font-semibold mb-3">Open ports ({scan.ports.length})</h3>
        <div className="flex flex-wrap gap-2">
          {scan.ports.map((p) => (
            <span key={p.id} className="rounded bg-slate-800 px-2.5 py-1 text-xs font-mono">
              {formatPortNumber(p.port)}
              {p.service?.product && (
                <span className="text-slate-400">
                  {' '}· {p.service.product}{p.service.version ? ` ${p.service.version}` : ''}
                </span>
              )}
            </span>
          ))}
        </div>
      </section>

      <section className="rounded-lg bg-slate-900 border border-slate-800 p-4">
        <h3 className="font-semibold mb-3">Findings</h3>
        <FindingTable findings={scan.findings} />
      </section>
    </Layout>
  )
}