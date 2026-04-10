const VALID_ROLES = new Set(['admin', 'soc_manager', 'analyst', 'viewer', 'observer'])

export const ROLE_LABELS = {
  admin: 'Administrator',
  soc_manager: 'SOC Manager',
  analyst: 'Analyst',
  viewer: 'Viewer',
  observer: 'Observer',
}

const TAB_ACCESS = {
  admin: ['dashboard', 'conflicts', 'dedup', 'alerts', 'search', 'attack', 'ai', 'soar', 'export', 'sources', 'integrations', 'admin'],
  soc_manager: ['dashboard', 'conflicts', 'dedup', 'alerts', 'search', 'attack', 'ai', 'soar', 'export', 'sources', 'integrations'],
  analyst: ['dashboard', 'conflicts', 'dedup', 'alerts', 'search', 'attack', 'ai', 'soar', 'export', 'sources', 'integrations'],
  viewer: ['dashboard', 'alerts', 'search', 'attack'],
  observer: ['dashboard', 'alerts'],
}

const CAPABILITY_ACCESS = {
  exportData: ['admin', 'soc_manager', 'analyst'],
  bulkActions: ['admin', 'soc_manager'],
  triggerFeedSync: ['admin', 'soc_manager'],
  manageIntegrations: ['admin', 'soc_manager'],
  blocklistExport: ['admin', 'soc_manager', 'analyst'],
  blocklistImport: ['admin', 'soc_manager'],
  adminPanel: ['admin'],
}
const ALL_TABS = Array.from(new Set(Object.values(TAB_ACCESS).flat()))

export function normalizeRole(inputRole) {
  const role = String(inputRole || '').trim().toLowerCase()
  return VALID_ROLES.has(role) ? role : 'analyst'
}

export function getRolePermissions(inputRole) {
  const role = normalizeRole(inputRole)
  const tabs = Object.fromEntries(
    ALL_TABS.map((tabId) => [tabId, TAB_ACCESS[role].includes(tabId)])
  )

  const permissions = {
    role,
    roleLabel: ROLE_LABELS[role],
    tabs,
  }

  Object.entries(CAPABILITY_ACCESS).forEach(([capability, allowedRoles]) => {
    permissions[capability] = allowedRoles.includes(role)
  })

  return permissions
}
