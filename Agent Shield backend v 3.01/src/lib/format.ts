import type { Severity } from './types'

export const formatDateTime = (iso: string) =>
  new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(iso))

export const formatRelative = (iso: string) => {
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low']

export const titleCase = (value: string) => value.charAt(0).toUpperCase() + value.slice(1)
