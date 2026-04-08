import { useEffect, useState } from 'react'
import axios from 'axios'

const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

function App() {
  const [stats, setStats] = useState(null)
  const [indicators, setIndicators] = useState([])
  const [sources, setSources] = useState(['all'])
  const [selectedSource, setSelectedSource] = useState('all')
  const [error, setError] = useState(null)

  useEffect(() => {
    async function fetchStats() {
      try {
        const response = await axios.get(`${apiUrl}/stats`)
        setStats(response.data)
      } catch (err) {
        setError('Unable to fetch dashboard stats')
      }
    }

    async function fetchSources() {
      try {
        const response = await axios.get(`${apiUrl}/sources`)
        setSources(['all', ...response.data])
      } catch (err) {
        setError('Unable to fetch source list')
      }
    }

    async function fetchIndicators(source = 'all') {
      try {
        const params = { limit: 10 }
        if (source !== 'all') {
          params.source = source
        }
        const response = await axios.get(`${apiUrl}/indicators`, { params })
        setIndicators(response.data)
      } catch (err) {
        setError('Unable to fetch indicators')
      }
    }

    fetchStats()
    fetchSources()
    fetchIndicators()
  }, [])

  useEffect(() => {
    async function fetchIndicators(source) {
      try {
        const params = { limit: 10 }
        if (source !== 'all') {
          params.source = source
        }
        const response = await axios.get(`${apiUrl}/indicators`, { params })
        setIndicators(response.data)
      } catch (err) {
        setError('Unable to fetch indicators')
      }
    }

    fetchIndicators(selectedSource)
  }, [selectedSource])

  return (
    <div className="app-shell">
      <header>
        <h1>Threat Intelligence Dashboard</h1>
        <p>Microservices dashboard for OpenCTI and MISP feeds.</p>
      </header>

      <div className="toolbar">
        <label htmlFor="source-filter">Source:</label>
        <select
          id="source-filter"
          value={selectedSource}
          onChange={(e) => setSelectedSource(e.target.value)}
        >
          {sources.map((source) => (
            <option value={source} key={source}>
              {source === 'all' ? 'All sources' : source}
            </option>
          ))}
        </select>
      </div>

      {error && <div className="banner error">{error}</div>}

      <section className="cards">
        <article>
          <h2>Total Indicators</h2>
          <strong>{stats ? stats.total_indicators : 'Loading...'}</strong>
        </article>
        <article>
          <h2>Latest Indicators</h2>
          <strong>{stats ? stats.latest_indicators.length : 'Loading...'}</strong>
        </article>
      </section>

      <section>
        <h2>Recent indicators</h2>
        <table>
          <thead>
            <tr>
              <th>Indicator</th>
              <th>Source</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {indicators.map((item) => (
              <tr key={item.id}>
                <td>{item.indicator}</td>
                <td>{item.source}</td>
                <td>{item.last_seen || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}

export default App
