import { useEffect, useState } from 'react'

export default function GeoMapPanel({ stats }) {
  const [geoData, setGeoData] = useState(null)

  useEffect(() => {
    if (stats?.geo_summary) {
      setGeoData(stats.geo_summary)
    }
  }, [stats])

  const flagEmoji = (country) => {
    const flags = {
      'China': '🇨🇳', 'United States': '🇺🇸', 'Russia': '🇷🇺', 'India': '🇮🇳',
      'Brazil': '🇧🇷', 'Germany': '🇩🇪', 'United Kingdom': '🇬🇧', 'France': '🇫🇷',
      'Japan': '🇯🇵', 'South Korea': '🇰🇷', 'Netherlands': '🇳🇱', 'Singapore': '🇸🇬',
      'Hong Kong': '🇭🇰', 'Canada': '🇨🇦', 'Australia': '🇦🇺', 'Ukraine': '🇺🇦',
      'Vietnam': '🇻🇳', 'Thailand': '🇹🇭', 'Indonesia': '🇮🇩', 'Malaysia': '🇲🇾',
      'Pakistan': '🇵🇰', 'Bangladesh': '🇧🇩', 'South Africa': '🇿🇦', 'Egypt': '🇪🇬',
      'Spain': '🇪🇸', 'Italy': '🇮🇹', 'Poland': '🇵🇱', 'Turkey': '🇹🇷',
      'Iran': '🇮🇷', 'North Korea': '🇰🇵', 'Taiwan': '🇹🇼', 'Myanmar': '🇲🇲',
    }
    return flags[country] || '🌍'
  }

  const countryName = (code) => {
    const names = {
      'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'IN': 'India',
      'BR': 'Brazil', 'DE': 'Germany', 'GB': 'United Kingdom', 'FR': 'France',
      'JP': 'Japan', 'KR': 'South Korea', 'NL': 'Netherlands', 'SG': 'Singapore',
      'HK': 'Hong Kong', 'CA': 'Canada', 'AU': 'Australia', 'UA': 'Ukraine',
      'VN': 'Vietnam', 'TH': 'Thailand', 'ID': 'Indonesia', 'MY': 'Malaysia',
      'PK': 'Pakistan', 'BD': 'Bangladesh', 'ZA': 'South Africa', 'EG': 'Egypt',
      'ES': 'Spain', 'IT': 'Italy', 'PL': 'Poland', 'TR': 'Turkey', 'IR': 'Iran',
      'KP': 'North Korea', 'TW': 'Taiwan', 'MM': 'Myanmar',
    }
    return names[code] || code
  }

  if (!geoData || geoData.total_mapped === 0) {
    return (
      <div className="text-center py-8 text-slate-400">
        <div className="text-3xl mb-2">🌍</div>
        <div className="text-sm">No geo data available</div>
        <div className="text-xs mt-1 text-slate-500">Enrich IPs with GeoIP to see distribution</div>
      </div>
    )
  }

  const countries = geoData.countries || []
  const asnData = geoData.asn || []
  const topLocations = geoData.top_locations || []
  const totalMapped = geoData.total_mapped || 0
  const countryCount = countries.length

  return (
    <div className="space-y-4">
      {/* Heat map visualization */}
      <div className="h-32 rounded-2xl relative overflow-hidden" style={{
        background: 'linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f172a 100%)'
      }}>
        <div className="absolute inset-0 opacity-30" style={{
          backgroundImage: 'radial-gradient(circle at 30% 40%, rgba(59,130,246,0.5) 0%, transparent 50%), radial-gradient(circle at 70% 60%, rgba(139,92,246,0.4) 0%, transparent 40%)'
        }}></div>
        
        {/* Attack origin heat dots */}
        {countries.slice(0, 8).map((c, i) => {
          const positions = {
            'China': { top: 35, left: 65 }, 'United States': { top: 30, left: 20 },
            'Russia': { top: 25, left: 55 }, 'India': { top: 45, left: 60 },
            'Vietnam': { top: 50, left: 68 }, 'Netherlands': { top: 25, left: 45 },
            'Germany': { top: 28, left: 48 }, 'Brazil': { top: 60, left: 30 },
          }
          const pos = positions[c.name] || { top: 30 + (i * 8), left: 20 + (i * 12) }
          const size = Math.min(8, Math.max(3, Math.log2(c.count) * 2))
          return (
            <div key={c.name} className="absolute rounded-full bg-accent animate-pulse-slow"
              style={{
                top: `${pos.top}%`, left: `${pos.left}%`,
                width: `${size}px`, height: `${size}px`,
                animationDelay: `${i * 0.3}s`
              }}>
              <div className="absolute inset-0 rounded-full bg-accent animate-ping opacity-40"></div>
            </div>
          )
        })}
        
        <div className="absolute inset-0 flex flex-col items-center justify-center text-white">
          <span className="text-2xl font-bold">{totalMapped.toLocaleString()}</span>
          <span className="text-xs text-slate-300">IOCs Mapped</span>
        </div>
      </div>

      {/* Country distribution */}
      <div className="space-y-2">
        <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Country Distribution</h4>
        {countries.slice(0, 6).map((c) => (
          <div key={c.name} className="flex items-center gap-3 p-2 rounded-xl hover:bg-slate-50 transition-colors">
            <span className="text-lg">{flagEmoji(c.name)}</span>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-slate-800">{c.name}</div>
              <div className="w-full h-1.5 bg-slate-100 rounded-full mt-1 overflow-hidden">
                <div className="h-full bg-gradient-to-r from-sky-400 to-sky-600 rounded-full" 
                  style={{ width: `${(c.count / totalMapped) * 100}%` }}></div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm font-bold text-slate-700">{c.count}</div>
              <div className="text-[10px] text-slate-400">{Math.round((c.count / totalMapped) * 100)}%</div>
            </div>
          </div>
        ))}
        {countryCount > 6 && (
          <div className="text-xs text-slate-400 text-center py-2">+{countryCount - 6} more countries</div>
        )}
      </div>

      {/* ASN / Hosting Provider */}
      {asnData.length > 0 && (
        <div className="pt-3 border-t border-slate-100">
          <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">ASN / Hosting Providers</h4>
          <div className="space-y-1.5 max-h-32 overflow-y-auto">
            {asnData.slice(0, 5).map((a) => (
              <div key={a.asn} className="flex items-center justify-between text-xs p-2 rounded-lg bg-slate-50">
                <span className="font-medium text-slate-600 truncate flex-1">{a.asn}</span>
                <span className="text-slate-400 ml-2">{a.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top locations with coordinates */}
      {topLocations.length > 0 && (
        <div className="pt-3 border-t border-slate-100">
          <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Recent Origins</h4>
          <div className="grid grid-cols-2 gap-2">
            {topLocations.slice(0, 4).map((loc, i) => (
              <div key={i} className="text-xs p-2 rounded-lg bg-slate-50 flex items-center gap-2">
                <span className="text-sm">{flagEmoji(loc.country)}</span>
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-slate-700 truncate">{loc.city || loc.country}</div>
                  <div className="text-[9px] text-slate-400">{loc.lat?.toFixed(2)}, {loc.lng?.toFixed(2)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}