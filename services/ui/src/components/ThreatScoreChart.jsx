import { useEffect, useRef, useState } from 'react'
import * as echarts from 'echarts'

export default function ThreatScoreChart({ stats }) {
  const chartRef = useRef(null)
  const [selectedDay, setSelectedDay] = useState(null)

  const timeline = stats?.timeline || []
  const events = stats?.events || []

  useEffect(() => {
    if (!chartRef.current || timeline.length === 0) return

    const chart = echarts.init(chartRef.current)

    const dates = timeline.map(d => d.date)
    const avgScores = timeline.map(d => d.avg_score)
    const maxScores = timeline.map(d => d.max_score)
    const counts = timeline.map(d => d.count)

    const eventMarkers = timeline
      .filter(d => events.some(e => e.date === d.date))
      .map(d => ({
        xAxis: d.date,
        label: { show: true, formatter: '⚠️', position: 'top', fontSize: 14 }
      }))

    const option = {
      grid: { top: 40, right: 20, bottom: 50, left: 50 },
      legend: {
        data: ['Avg Score', 'Max Score', 'IOC Count'],
        top: 0,
        textStyle: { color: '#64748b', fontSize: 11 }
      },
      xAxis: {
        type: 'category',
        data: dates,
        axisLabel: { 
          color: '#64748b', 
          fontSize: 10,
          rotate: 45,
          formatter: (value) => {
            const date = new Date(value)
            return `${date.getMonth()+1}/${date.getDate()}`
          }
        },
        axisTick: { show: true, alignWithLabel: true },
        axisLine: { lineStyle: { color: '#e2e8f0' } },
      },
      yAxis: [
        {
          type: 'value',
          name: 'Score',
          max: 100,
          position: 'left',
          axisLabel: { color: '#64748b', fontSize: 10 },
          splitLine: { lineStyle: { color: '#f1f5f9' } },
        },
        {
          type: 'value',
          name: 'Count',
          position: 'right',
          axisLabel: { color: '#64748b', fontSize: 10 },
          splitLine: { show: false },
        }
      ],
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#0f172a',
        borderColor: '#0f172a',
        textStyle: { color: '#fff', fontSize: 12 },
        formatter: (params) => {
          const dayData = timeline[params[0].dataIndex]
          const date = new Date(dayData.date).toLocaleDateString()
          let html = `<div style="font-weight:600;margin-bottom:6px">📅 ${date}</div>`
          
          params.forEach(p => {
            const color = p.seriesName === 'Avg Score' ? '#8b5cf6' : p.seriesName === 'Max Score' ? '#ef4444' : '#3b82f6'
            html += `<div>${p.marker} ${p.seriesName}: <span style="font-weight:700;color:${color}">${p.value}</span></div>`
          })
          
          if (dayData) {
            html += `<div style="margin-top:6px;padding-top:6px;border-top:1px solid #334155;font-size:10px">`
            html += `<span style="color:#ef4444">● ${dayData.critical} critical</span> `
            html += `<span style="color:#f97316">● ${dayData.high} high</span> `
            html += `<span style="color:#eab308">● ${dayData.medium} medium</span> `
            html += `<span style="color:#22c55e">● ${dayData.low} low</span>`
            html += `</div>`
          }
          
          return html
        }
      },
      series: [
        {
          name: 'Avg Score',
          type: 'line',
          smooth: true,
          symbol: 'circle',
          symbolSize: 8,
          yAxisIndex: 0,
          lineStyle: { width: 3, color: '#8b5cf6' },
          itemStyle: { color: '#8b5cf6', borderWidth: 2, borderColor: '#fff' },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(139,92,246,0.2)' },
              { offset: 1, color: 'rgba(139,92,246,0.02)' },
            ]),
          },
          data: avgScores,
          markPoint: {
            data: eventMarkers,
            symbolSize: 20,
          }
        },
        {
          name: 'Max Score',
          type: 'line',
          smooth: true,
          symbol: 'circle',
          symbolSize: 6,
          yAxisIndex: 0,
          lineStyle: { width: 2, color: '#ef4444', type: 'dashed' },
          itemStyle: { color: '#ef4444' },
          data: maxScores,
        },
        {
          name: 'IOC Count',
          type: 'bar',
          yAxisIndex: 1,
          barWidth: '30%',
          itemStyle: { 
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: '#3b82f6' },
              { offset: 1, color: '#1d4ed8' },
            ]),
            borderRadius: [4, 4, 0, 0]
          },
          data: counts,
        }
      ],
    }

    chart.setOption(option)

    chart.on('click', (params) => {
      if (params.componentType === 'series') {
        const dayIndex = params.dataIndex
        if (timeline[dayIndex]) {
          setSelectedDay(timeline[dayIndex])
        }
      }
    })

    const resizeObserver = new ResizeObserver(() => chart.resize())
    resizeObserver.observe(chartRef.current)

    return () => {
      resizeObserver.disconnect()
      chart.dispose()
    }
  }, [timeline, events])

  if (timeline.length === 0) {
    return (
      <div className="h-72 flex items-center justify-center text-slate-400 text-sm">
        <div className="text-center">
          <div className="text-3xl mb-2">📊</div>
          <div>No threat score timeline available</div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div ref={chartRef} className="h-72 w-full" />
      
      {/* Drill-down panel */}
      {selectedDay && (
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-bold text-slate-900">
              📅 Details for {new Date(selectedDay.date).toLocaleDateString()}
            </h4>
            <button onClick={() => setSelectedDay(null)} className="text-slate-400 hover:text-slate-600">
              <span className="material-symbols-outlined text-sm">close</span>
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-white border border-slate-100">
              <div className="text-xs text-slate-400 font-medium">Avg Score</div>
              <div className="text-xl font-bold text-purple-600">{selectedDay.avg_score}</div>
            </div>
            <div className="p-3 rounded-lg bg-white border border-slate-100">
              <div className="text-xs text-slate-400 font-medium">Max Score</div>
              <div className="text-xl font-bold text-red-600">{selectedDay.max_score}</div>
            </div>
            <div className="p-3 rounded-lg bg-white border border-slate-100">
              <div className="text-xs text-slate-400 font-medium">IOCs</div>
              <div className="text-xl font-bold text-slate-700">{selectedDay.count}</div>
            </div>
            <div className="p-3 rounded-lg bg-white border border-slate-100">
              <div className="text-xs text-slate-400 font-medium">Change</div>
              {stats?.comparison && (
                <div className={`text-xl font-bold ${selectedDay.count > stats.comparison.prior_period_count / 7 ? 'text-red-600' : 'text-emerald-600'}`}>
                  {((selectedDay.count - stats.comparison.prior_period_count / 7) / (stats.comparison.prior_period_count / 7) * 100).toFixed(0)}%
                </div>
              )}
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <span className="text-xs font-medium text-slate-500">Severity breakdown:</span>
            <span className="text-xs text-red-600">{selectedDay.critical} critical</span>
            <span className="text-xs text-orange-600">{selectedDay.high} high</span>
            <span className="text-xs text-yellow-600">{selectedDay.medium} medium</span>
            <span className="text-xs text-green-600">{selectedDay.low} low</span>
          </div>
        </div>
      )}

      {/* Comparison summary */}
      {stats?.comparison && (
        <div className="flex items-center justify-between text-xs text-slate-500 px-2">
          <span>vs. prior period ({stats.comparison.prior_period_count} IOCs)</span>
          <span>📈 {stats.comparison.current_period_count} total this period</span>
        </div>
      )}
    </div>
  )
}