import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { logout } from '../api'
import { severityColor } from '../theme'

const navItems = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/targets', label: 'Targets' },
  { to: '/scans', label: 'Scans' },
  { to: '/compare', label: 'Compare' },
  { to: '/assets', label: 'Assets' },
]

export default function Layout({ children }) {
  const navigate = useNavigate()
  return (
    <div className="min-h-screen flex">
      <aside className="w-56 shrink-0 bg-slate-900 border-r border-slate-800 p-4 flex flex-col gap-1">
        <h1 className="text-lg font-bold tracking-tight mb-4">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-sev-critical mr-2" />
          Network Mapper
        </h1>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `rounded px-3 py-2 text-sm font-medium ${
                isActive ? 'bg-slate-800 text-white' : 'text-slate-400 hover:bg-slate-800/60'
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
        <div className="mt-auto flex items-center justify-between">
          <span className="text-xs text-slate-500">admin</span>
          <button
            onClick={() => {
              logout()
              navigate('/login')
            }}
            className="text-xs text-slate-400 hover:text-white"
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 p-6 overflow-auto">{children}</main>
    </div>
  )
}

export function SeverityDot({ severity }) {
  return (
    <span
      title={severity}
      className="inline-block w-2.5 h-2.5 rounded-full"
      style={{ backgroundColor: severityColor(severity) }}
    />
  )
}

export function SeverityBadge({ severity }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold"
      style={{ backgroundColor: `${severityColor(severity)}22`, color: severityColor(severity) }}
    >
      <SeverityDot severity={severity} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  )
}

export function StatusBadge({ status }) {
  const styles = {
    queued: 'bg-slate-600',
    running: 'bg-blue-500',
    completed: 'bg-emerald-500',
    failed: 'bg-red-500',
  }
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold text-white ${styles[status] || styles.queued}`}>
      {status}
    </span>
  )
}

export function Loading() {
  return <div className="text-sm text-slate-400 py-8">Loading…</div>
}

export function ErrorBox({ message }) {
  return <div className="text-sm text-red-400 py-8">{message}</div>
}

export function StatCard({ label, value, color = '#e2e8f0' }) {
  return (
    <div className="rounded-lg bg-slate-900 border border-slate-800 p-4">
      <div className="text-xs text-slate-400">{label}</div>
      <div className="text-2xl font-bold mt-1" style={{ color }}>
        {value}
      </div>
    </div>
  )
}