import React from 'react'
import { Link } from 'react-router-dom'
import { SeverityBadge } from './Layout'
import { formatScore } from '../theme'

export default function FindingTable({ findings }) {
  if (!findings?.length) {
    return <div className="text-sm text-slate-400 py-6">No findings.</div>
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-slate-400 text-left">
          <tr>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">Risk</th>
            <th className="px-3 py-2">CVE</th>
            <th className="px-3 py-2">CVSS</th>
            <th className="px-3 py-2">EPSS</th>
            <th className="px-3 py-2">KEV</th>
            <th className="px-3 py-2">Confidence</th>
            <th className="px-3 py-2">Description</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {findings.map((f) => (
            <tr key={f.id} className="hover:bg-slate-900/60 align-top">
              <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
              <td className="px-3 py-2 font-semibold">{formatScore(f.risk_score)}</td>
              <td className="px-3 py-2 font-mono text-blue-300">{f.cve_id}</td>
              <td className="px-3 py-2">{formatScore(f.cvss_score)}</td>
              <td className="px-3 py-2">{formatScore(f.epss_score)}</td>
              <td className="px-3 py-2">
                {f.kev ? <span className="text-orange-300 font-bold">Yes</span> : <span className="text-slate-600">No</span>}
              </td>
              <td className="px-3 py-2 capitalize">{f.confidence}</td>
              <td className="px-3 py-2 text-slate-300 min-w-[280px]">
                {f.description}
                {f.remediation && (
                  <div className="mt-1 text-xs text-slate-500">Fix: {f.remediation}</div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function FindingLinkRow({ scanId }) {
  return (
    <div className="text-sm text-slate-400">
      <Link to={`/scans/${scanId}`} className="text-blue-400 hover:underline">
        View full findings
      </Link>
    </div>
  )
}