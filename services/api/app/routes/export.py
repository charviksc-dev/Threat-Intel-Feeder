import csv
import io
import json
import logging
from datetime import datetime
from typing import List, Dict, Any

import pandas as pd
from fpdf import FPDF
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from elasticsearch import AsyncElasticsearch

from ..dependencies import get_elasticsearch
from ..config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["export"])

class PDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'Neev TIP - Threat Intelligence Report', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

@router.get("/export/csv")
async def export_csv(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float = Query(0),
    limit: int = Query(2000, ge=1, le=10000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as Excel-friendly CSV file."""
    indicators = await _fetch_indicators(es, source, severity, min_score, limit)
    
    if not indicators:
        return JSONResponse(status_code=404, content={"detail": "No data found"})

    df = pd.DataFrame(indicators)
    
    # Standardize columns for Excel
    cols = ['indicator', 'type', 'source', 'confidence_score', 'severity', 'first_seen', 'last_seen']
    present_cols = [c for c in cols if c in df.columns]
    df = df[present_cols]

    stream = io.StringIO()
    df.to_csv(stream, index=False, quoting=csv.QUOTE_NONNUMERIC)
    
    return StreamingResponse(
        io.BytesIO(stream.getvalue().encode('utf-8-sig')), # utf-8-sig for Excel compatibility
        media_type="application/octet-stream", # Force download on Mac
        headers={
            "Content-Disposition": f"attachment; filename=neeve-iocs-{datetime.now().strftime('%Y%m%d')}.csv"
        },
    )

@router.get("/export/xlsx")
async def export_xlsx(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float = Query(0),
    limit: int = Query(2000, ge=1, le=10000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as Excel (XLSX) file."""
    indicators = await _fetch_indicators(es, source, severity, min_score, limit)
    
    if not indicators:
        return JSONResponse(status_code=404, content={"detail": "No data found"})

    df = pd.DataFrame(indicators)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Intelligence')
    
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/octet-stream", # Force download on Mac
        headers={
            "Content-Disposition": f"attachment; filename=neeve-iocs-{datetime.now().strftime('%Y%m%d')}.xlsx"
        },
    )

@router.get("/export/pdf")
async def export_pdf(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float = Query(0),
    limit: int = Query(500, ge=1, le=1000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as PDF report."""
    indicators = await _fetch_indicators(es, source, severity, min_score, limit)
    
    if not indicators:
        return JSONResponse(status_code=404, content={"detail": "No data found"})

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("helvetica", size=9)
    
    # Table Header
    pdf.set_fill_color(220, 230, 240)
    pdf.cell(60, 10, "Indicator", 1, 0, 'C', 1)
    pdf.cell(20, 10, "Type", 1, 0, 'C', 1)
    pdf.cell(30, 10, "Source", 1, 0, 'C', 1)
    pdf.cell(15, 10, "Score", 1, 0, 'C', 1)
    pdf.cell(20, 10, "Severity", 1, 0, 'C', 1)
    pdf.cell(45, 10, "First Seen", 1, 1, 'C', 1)

    pdf.set_fill_color(255, 255, 255)
    for ind in indicators:
        pdf.cell(60, 8, str(ind.get("indicator", ""))[:32], 1)
        pdf.cell(20, 8, str(ind.get("type", "")), 1)
        pdf.cell(30, 8, str(ind.get("source", "")), 1)
        pdf.cell(15, 8, str(ind.get("confidence_score", "")), 1)
        pdf.cell(20, 8, str(ind.get("severity", "")), 1)
        pdf.cell(45, 8, str(ind.get("first_seen", ""))[:19], 1, 1)

    return StreamingResponse(
        io.BytesIO(pdf.output()),
        media_type="application/octet-stream", # Force download on Mac
        headers={
            "Content-Disposition": f"attachment; filename=neeve-report-{datetime.now().strftime('%Y%m%d')}.pdf"
        },
    )

@router.get("/export/json")
async def export_json(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float = Query(0),
    limit: int = Query(1000, ge=1, le=10000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as JSON file."""
    indicators = await _fetch_indicators(es, source, severity, min_score, limit)

    return JSONResponse(
        content={
            "exported_at": datetime.utcnow().isoformat(),
            "count": len(indicators),
            "indicators": indicators,
        },
        headers={
            "Content-Disposition": f"attachment; filename=neeve-indicators-{datetime.now().strftime('%Y%m%d')}.json"
        },
    )

@router.get("/export/ioc-list")
async def export_ioc_list(
    format: str = Query("plain", description="plain, csv_ips, csv_domains"),
    source: str | None = Query(None),
    min_score: float = Query(40),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Simple IOC list export for quick use."""
    indicators = await _fetch_indicators(es, source, None, min_score, 10000)

    if format == "csv_ips":
        ips = [i["indicator"] for i in indicators if i.get("type") in ("ipv4", "ipv6")]
        return StreamingResponse(
            io.BytesIO("\n".join(ips).encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=ips.csv"},
        )
    elif format == "csv_domains":
        domains = [i["indicator"] for i in indicators if i.get("type") == "domain"]
        return StreamingResponse(
            io.BytesIO("\n".join(domains).encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=domains.csv"},
        )
    else:
        lines = [f"{i['indicator']}" for i in indicators]
        return StreamingResponse(
            io.BytesIO("\n".join(lines).encode()),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=iocs.txt"},
        )

@router.post("/bulk/tag")
async def bulk_tag(
    indicator_ids: List[str],
    tags: List[str],
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Add tags to multiple indicators at once."""
    updated = 0
    for iid in indicator_ids:
        try:
            doc = await es.get(index=settings.ELASTICSEARCH_INDEX, id=iid)
            existing_tags = doc["_source"].get("tags", [])
            new_tags = list(set(existing_tags + tags))
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=iid,
                body={"doc": {"tags": new_tags}},
            )
            updated += 1
        except Exception:
            pass

    return {"updated": updated, "total": len(indicator_ids)}

@router.post("/bulk/block")
async def bulk_block(
    indicator_ids: List[str],
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Mark multiple indicators as blocked and add to blocklist."""
    blocked = 0
    for iid in indicator_ids:
        try:
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=iid,
                body={"doc": {"tags": ["blocked", "firewall-added"], "blocked": True}},
            )
            blocked += 1
        except Exception:
            pass

    return {"blocked": blocked, "total": len(indicator_ids)}

async def _fetch_indicators(es: AsyncElasticsearch, source: str | None, severity: str | None, min_score: float, limit: int) -> List[Dict[str, Any]]:
    """Helper to fetch indicators with filters."""
    filters = [{"range": {"confidence_score": {"gte": min_score}}}]
    if source:
        filters.append({"term": {"source": source}})
    if severity:
        filters.append({"term": {"severity": severity}})

    body = {
        "query": {"bool": {"filter": filters}},
        "size": limit,
        "sort": [{"confidence_score": "desc"}],
    }

    try:
        response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        logger.error(f"ES search error in export: {e}")
        return []
