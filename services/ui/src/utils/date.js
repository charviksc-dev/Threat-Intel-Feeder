export function formatDate(value) {
  if (!value) return '—'
  
  let date
  if (value instanceof Date) {
    date = value
  } else if (typeof value === 'string') {
    if (value.includes('+00') || value.endsWith('Z')) {
      date = new Date(value)
    } else if (/^\d{4}-\d{2}-\d{2}/.test(value)) {
      date = new Date(value + 'Z')
    } else {
      date = new Date(value)
    }
  } else if (typeof value === 'number') {
    date = new Date(value)
  } else {
    return '—'
  }
  
  if (isNaN(date.getTime())) {
    return '—'
  }
  
  return date
}

export function formatDateTime(value) {
  const date = formatDate(value)
  if (date === '—') return '—'
  return date.toLocaleString()
}

export function formatTime(value) {
  const date = formatDate(value)
  if (date === '—') return '—'
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
}

export function formatDateOnly(value) {
  const date = formatDate(value)
  if (date === '—') return '—'
  return date.toLocaleDateString()
}

export function formatRelativeTime(value) {
  const date = formatDate(value)
  if (date === '—') return '—'
  
  const now = new Date()
  const diffMs = now - date
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)
  
  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}