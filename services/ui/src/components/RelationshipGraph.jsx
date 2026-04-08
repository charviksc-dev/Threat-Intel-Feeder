export default function RelationshipGraph({ data }) {
  // Build a simple node graph from indicators
  const nodes = data.slice(0, 12).map((item, i) => {
    const angle = (i / Math.min(data.length, 12)) * Math.PI * 2
    const radius = 35 + Math.random() * 15
    return {
      ...item,
      x: 50 + Math.cos(angle) * radius,
      y: 50 + Math.sin(angle) * radius,
      size: Math.max(4, (item.confidence_score || 20) / 10),
    }
  })

  const typeColors = {
    ipv4: '#3b82f6', ipv6: '#3b82f6', domain: '#8b5cf6',
    url: '#f59e0b', hash: '#ef4444', email: '#10b981',
  }

  if (data.length === 0) {
    return (
      <div className="text-center py-8 text-slate-400">
        <div className="text-3xl mb-2">🕸️</div>
        <div className="text-sm">No relationship data</div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="h-48 rounded-2xl bg-slate-50 relative overflow-hidden border border-slate-100">
        {/* Connection lines */}
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100">
          {nodes.map((node, i) => {
            const next = nodes[(i + 1) % nodes.length]
            return (
              <line key={`line-${i}`}
                x1={node.x} y1={node.y} x2={next.x} y2={next.y}
                stroke="#cbd5e1" strokeWidth="0.3" strokeDasharray="2,2" />
            )
          })}
        </svg>
        {/* Nodes */}
        {nodes.map((node, i) => (
          <div key={i} className="absolute transform -translate-x-1/2 -translate-y-1/2 group"
            style={{ left: `${node.x}%`, top: `${node.y}%` }}>
            <div className="rounded-full shadow-md border-2 border-white transition-transform duration-200 group-hover:scale-150 cursor-pointer"
              style={{
                width: `${node.size * 2 + 8}px`,
                height: `${node.size * 2 + 8}px`,
                backgroundColor: typeColors[node.type] || '#64748b',
              }}>
            </div>
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-slate-900 text-white text-[10px] rounded-lg opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-10">
              {node.indicator?.substring(0, 30)}
              <div className="text-slate-400">{node.source}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {Object.entries(typeColors).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }}></div>
            <span className="text-[11px] text-slate-500 capitalize">{type}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
