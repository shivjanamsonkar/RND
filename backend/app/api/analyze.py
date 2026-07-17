"""
POST /analyze  — submit source code for security analysis.
"""
import os
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from app.models.report import Report
from app.services.analysis_service import analyze_code, SUPPORTED_LANGUAGES, EXTENSION_TO_LANGUAGE
from app.services.auth_service import require_api_key
from app.services.report_service import save_report

router = APIRouter()

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


@router.post(
    "/analyze",
    summary="Submit code for security analysis",
    response_model=Report,
    status_code=status.HTTP_201_CREATED,
)
async def analyze_endpoint(
    file: UploadFile | None = File(default=None),
    code: str | None = Form(default=None),
    language: str | None = Form(default=None),
    filename: str = Form(default="uploaded_code.txt"),
    _: str = Depends(require_api_key),
):
    """
    Submit source code for security analysis.

    Supply **either** a `file` upload **or** raw `code` in the form body.

    - `language` (optional): one of python, javascript, typescript, java, c, cpp, go, ruby, php.
      If omitted, the language is inferred from the filename extension.
    - `filename` (optional): used for display purposes and language inference.
    """
    if file is not None:
        raw = await file.read(MAX_FILE_SIZE + 1)
        if len(raw) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds the {MAX_FILE_SIZE // 1024} KB limit.",
            )
        try:
            source_code = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Could not decode file as UTF-8.",
            )
        fname = file.filename or filename
    elif code is not None:
        source_code = code
        fname = filename
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either a `file` upload or a `code` form field.",
        )

    # Normalise language
    if language:
        lang = language.lower()
        if lang not in SUPPORTED_LANGUAGES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported language '{language}'. Supported: {sorted(SUPPORTED_LANGUAGES)}",
            )
    else:
        ext = os.path.splitext(fname)[1].lower()
        lang = EXTENSION_TO_LANGUAGE.get(ext)

    report = analyze_code(source_code, fname, lang)
    save_report(report)
    return report
