"""
GET /reports            — list all stored reports (summary)
GET /reports/{id}       — full report as JSON
GET /reports/{id}/html  — full report as HTML
GET /reports/{id}/pdf   — full report as PDF
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response

from app.models.report import Report
from app.services.auth_service import require_api_key
from app.services.report_service import get_report, list_reports, generate_html, generate_pdf

router = APIRouter()


@router.get(
    "/reports",
    summary="List all scan reports",
)
def list_reports_endpoint(_: str = Depends(require_api_key)):
    return list_reports()


@router.get(
    "/reports/{report_id}",
    response_model=Report,
    summary="Get a full report as JSON",
)
def get_report_json(report_id: str, _: str = Depends(require_api_key)):
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    return report


@router.get(
    "/reports/{report_id}/html",
    response_class=HTMLResponse,
    summary="Get a full report as HTML",
)
def get_report_html(report_id: str, _: str = Depends(require_api_key)):
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    return HTMLResponse(content=generate_html(report))


@router.get(
    "/reports/{report_id}/pdf",
    summary="Get a full report as PDF (or HTML if weasyprint is unavailable)",
)
def get_report_pdf(report_id: str, _: str = Depends(require_api_key)):
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    pdf_bytes = generate_pdf(report)
    media_type = (
        "application/pdf"
        if pdf_bytes[:4] == b"%PDF"
        else "text/html"
    )
    return Response(
        content=pdf_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.pdf"'},
    )
