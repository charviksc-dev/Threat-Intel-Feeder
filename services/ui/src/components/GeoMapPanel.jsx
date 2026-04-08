export default function GeoMapPanel({ indicators }) {
  const geoIndicators = indicators.filter(item => item.geo && item.geo.country)

  // Aggregate by country
  const countryMap = {}
  geoIndicators.forEach(item => {
    const country = item.geo.country
    if (!countryMap[country]) {
      countryMap[country] = { count: 0, city: item.geo.city || '', lat: item.geo.latitude, lng: item.geo.longitude }
    }
    countryMap[country].count++
  })

  const topCountries = Object.entries(countryMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6)

  const flagEmoji = (country) => {
    const flags = {
      China: '🇨🇳', 'United States': '🇺🇸', Russia: '🇷🇺', India: '🇮🇳',
      Brazil: '🇧🇷', Germany: '🇩🇪', 'United Kingdom': '🇬🇧', France: '🇫🇷',
      Japan: '🇯🇵', 'South Korea': '🇰🇷', Netherlands: '🇳🇱', Singapore: '🇸🇬',
      'Hong Kong': '🇭🇰', Canada: '🇨🇦', Australia: '🇦🇺', Ukraine: '🇺🇦',
    }
    return flags[country] || '🌍'
  }

  if (geoIndicators.length === 0) {
    return (
      <div className="text-center py-8 text-slate-400">
        <div className="text-3xl mb-2">🌍</div>
        <div className="text-sm">No geo data available</div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Map placeholder with gradient */}
      <div className="h-44 rounded-2xl relative overflow-hidden" style={{
        background: 'linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f172a 100%)'
      }}>
        <div className="absolute inset-0 opacity-20" style={{
          backgroundImage: 'radial-gradient(circle at 30% 40%, rgba(59,130,246,0.4) 0%, transparent 50%), radial-gradient(circle at 70% 60%, rgba(139,92,246,0.3) 0%, transparent 40%)'
        }}></div>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-white">
          <span className="text-2xl font-bold">{Object.keys(countryMap).length}</span>
          <span className="text-xs text-slate-300">Countries Detected</span>
        </div>
        {/* Animated dots for top locations */}
        {topCountries.slice(0, 3).map(([country, data], i) => (
          <div key={country} className="absolute w-3 h-3 rounded-full bg-accent animate-pulse-slow"
            style={{ top: `${25 + i * 20}%`, left: `${20 + i * 25}%`, animationDelay: `${i * 0.5}s` }}>
            <div className="absolute inset-0 rounded-full bg-accent animate-ping opacity-30"></div>
          </div>
        ))}
      </div>

      {/* Country list */}
      <div className="space-y-2">
        {topCountries.map(([country, data]) => (
          <div key={country} className="flex items-center gap-3 p-2.5 rounded-xl hover:bg-slate-50 transition-colors">
            <span className="text-lg">{flagEmoji(country)}</span>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-800">{country}</div>
              <div className="text-[11px] text-slate-400">{data.city || 'Multiple cities'}</div>
            </div>
            <div className="text-right">
              <div className="text-sm font-bold text-slate-700">{data.count}</div>
              <div className="text-[10px] text-slate-400">IOCs</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
