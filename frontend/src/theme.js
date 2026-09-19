export const SEVERITY_COLORS = {
  none: '#2F3E46',
  low: '#2A9D8F',
  medium: '#E9C46A',
  high: '#F4A261',
  critical: '#E76F51',
}

export function severityColor(severity) {
  return SEVERITY_COLORS[(severity || 'none').toLowerCase()] || SEVERITY_COLORS.none
}

export function severityLabel(severity) {
  const s = (severity || 'none').toLowerCase()
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export function formatTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function formatScore(value) {
  if (value === null || value === undefined) return '—'
  return Number(value).toFixed(2)
}

export function formatPortNumber(port) {
  const names = {
    21: 'ftp', 22: 'ssh', 25: 'smtp', 80: 'http', 443: 'https',
    3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 27017: 'mongodb',
  }
  return `${port}/${names[port] || 'tcp'}`
}