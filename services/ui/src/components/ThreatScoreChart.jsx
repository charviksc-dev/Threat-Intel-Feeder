import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'

export default function ThreatScoreChart({ indicators }) {
  const chartRef = useRef(null)

  useEffect(() => {
    if (!chartRef.current || indicators.length === 0) return

    const chart = echarts.init(chartRef.current)

    const scores = indicators.map(item => item.confidence_score ?? 0)
    const labels = indicators.map((item, i) => {
      const ind = item.indicator || ''
      return ind.length > 20 ? ind.substring(0, 18) + '...' : ind
    })

    const option = {
      grid: { top: 20, right: 16, bottom: 28, left: 44 },
      xAxis: {
        type: 'category',
        data: labels,
        axisLabel: { show: false },
        axisTick: { show: false },
        axisLine: { lineStyle: { color: '#e2e8f0' } },
      },
      yAxis: {
        type: 'value',
        max: 100,
        splitNumber: 4,
        axisLabel: { color: '#94a3b8', fontSize: 11 },
        splitLine: { lineStyle: { color: '#f1f5f9' } },
      },
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#0f172a',
        borderColor: '#0f172a',
        textStyle: { color: '#fff', fontSize: 12 },
        formatter: (params) => {
          const p = params[0]
          const ind = indicators[p.dataIndex]
          return `<div style="font-weight:600;margin-bottom:4px">${ind?.indicator || ''}</div>
                  <div>Score: <span style="color:${p.value >= 70 ? '#ef4444' : p.value >= 40 ? '#f59e0b' : '#10b981'};font-weight:700">${p.value}</span></div>
                  <div style="color:#94a3b8;font-size:11px">Source: ${ind?.source || ''}</div>`
        },
      },
      series: [
        {
          type: 'line',
          smooth: true,
          symbol: 'circle',
          symbolSize: 6,
          lineStyle: { width: 2.5, color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
            { offset: 0, color: '#3b82f6' },
            { offset: 1, color: '#8b5cf6' },
          ])},
          itemStyle: { color: '#3b82f6', borderWidth: 2, borderColor: '#fff' },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(59,130,246,0.15)' },
              { offset: 1, color: 'rgba(59,130,246,0.01)' },
            ]),
          },
          data: scores,
        },
      ],
    }

    chart.setOption(option)

    const resizeObserver = new ResizeObserver(() => chart.resize())
    resizeObserver.observe(chartRef.current)

    return () => {
      resizeObserver.disconnect()
      chart.dispose()
    }
  }, [indicators])

  if (indicators.length === 0) {
    return (
      <div className="h-72 flex items-center justify-center text-slate-400 text-sm">
        <div className="text-center">
          <div className="text-3xl mb-2">📊</div>
          <div>No threat score data available</div>
        </div>
      </div>
    )
  }

  return <div ref={chartRef} className="h-72 w-full" />
}
