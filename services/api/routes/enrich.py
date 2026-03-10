from __future__ import annotations

from fastapi import APIRouter


from fastapi import HTTPException
from ..models import EnrichmentResponse, CertificateOut

router = APIRouter(tags=["Enrichment"])


def _get_db():
    from ..main import db
    return db




# Enrich by SHA value (dedicated endpoint)
@router.get(
    "/enrich/sha/{sha_value}",
    response_model=EnrichmentResponse,
    summary="Enrich certificate by SHA value",
    description="Returns enrichment for a certificate by its SHA-256 fingerprint."
)
async def enrich_by_sha(sha_value: str):
    db = _get_db()
    cert_row = await db.fetchrow(
        "SELECT * FROM ct_certs WHERE fingerprint_sha256 = {fp:String} AND not_after > now()",
        {"fp": sha_value},
        endpoint="enrich_by_sha"
    )
    cert = CertificateOut(**cert_row) if cert_row else None
    if not cert:
        raise HTTPException(status_code=404, detail="Valid certificate not found")
    enrichment = {
        "dns_name_count": len(cert.dns_names) if cert.dns_names else 0,
        "issuer": cert.issuer,
        "validity_days": (cert.not_after - cert.not_before).days if cert.not_after and cert.not_before else None
    }
    return EnrichmentResponse(
        query=sha_value,
        certificate=cert,
        enrichment=enrichment,
        ip_matches=None
    )

# Enrich by domain (returns all valid certs for a domain)
@router.get(
    "/enrich/domain/{domain}",
    response_model=EnrichmentResponse,
    summary="Enrich certificates by domain",
    description="Returns all valid certificates for a given domain name."
)
async def enrich_by_domain(domain: str):
    db = _get_db()
    rows = await db.fetch(
        "SELECT * FROM ct_certs WHERE has(dns_names, {domain:String}) AND not_after > now()",
        {"domain": domain},
        endpoint="enrich_by_domain"
    )
    certs = [CertificateOut(**row) for row in rows] if rows else []
    if not certs:
        raise HTTPException(status_code=404, detail="No valid certificates found for this domain")
    enrichment = {
        "cert_count": len(certs),
        "domain": domain
    }
    return EnrichmentResponse(
        query=domain,
        certificate=None,
        enrichment=enrichment,
        ip_matches=certs
    )
