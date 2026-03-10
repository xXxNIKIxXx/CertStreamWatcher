from __future__ import annotations

from fastapi import APIRouter

from ..models import EnrichmentResponse

router = APIRouter(tags=["Enrichment"])


def _get_db():
    from ..main import db
    return db


@router.get(
    "/enrich/{fingerprint}",
    response_model=EnrichmentResponse,
    summary="Certificate enrichment",
    description=(
        "Enrich a certificate by its SHA-256 fingerprint. "
        "Returns detailed information about the certificate, including "
        "subject, issuer, validity period, and more."
    )
)
async def enrich_certificate(fingerprint: str):
    db = _get_db()
    return EnrichmentResponse(query=fingerprint)
