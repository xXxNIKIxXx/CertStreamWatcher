"""Certificate query endpoints (ClickHouse backend)."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from ..config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from ..models import (
    CertificateListResponse,
    CertificateOut,
    PaginationMeta,
)

router = APIRouter(prefix="/certificates", tags=["Certificates"])


def _get_db():
    from ..main import db
    return db


# ---------------------------------------------------------------------------
# List / search
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=CertificateListResponse,
    summary="List certificates",
    description=(
        "Paginated list of certificates with optional filtering by subject, "
        "issuer, domain (dns_names array) and time range."
    ),
)
async def list_certificates(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Results per page"),
    subject: Optional[str] = Query(None, description="Filter by subject (ilike)"),
    issuer: Optional[str] = Query(None, description="Filter by issuer (ilike)"),
    domain: Optional[str] = Query(None, description="Filter by DNS name (exact array element match)"),
    fingerprint: Optional[str] = Query(None, description="Exact SHA-256 fingerprint"),
    since: Optional[datetime] = Query(None, description="Certificates logged after this time"),
    until: Optional[datetime] = Query(None, description="Certificates logged before this time"),
    sort: str = Query("ts", description="Sort column", regex="^(ts|subject|issuer|not_before|not_after)$"),
    order: str = Query("desc", description="Sort order", regex="^(asc|desc)$"),
    db=Depends(_get_db),
):
    conditions: list[str] = []
    params: dict = {}
    idx = 0

    if subject:
        params[f"p{idx}"] = f"%{subject}%"
        conditions.append(f"ilike(subject, {{p{idx}:String}})")
        idx += 1
    if issuer:
        params[f"p{idx}"] = f"%{issuer}%"
        conditions.append(f"ilike(issuer, {{p{idx}:String}})")
        idx += 1
    if domain:
        params[f"p{idx}"] = domain
        conditions.append(f"has(dns_names, {{p{idx}:String}})")
        idx += 1
    if fingerprint:
        params[f"p{idx}"] = fingerprint
        conditions.append(f"fingerprint_sha256 = {{p{idx}:String}}")
        idx += 1
    if since:
        params[f"p{idx}"] = since
        conditions.append(f"ts >= {{p{idx}:DateTime64(3)}}")
        idx += 1
    if until:
        params[f"p{idx}"] = until
        conditions.append(f"ts <= {{p{idx}:DateTime64(3)}}")
        idx += 1

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    allowed_sort = {"ts", "subject", "issuer", "not_before", "not_after"}
    sort_col = sort if sort in allowed_sort else "ts"
    sort_dir = "ASC" if order == "asc" else "DESC"
    offset = (page - 1) * page_size

    count_sql = f"SELECT count() FROM ct_certs {where}"
    total = await db.fetchval(count_sql, params, endpoint="list_certificates") or 0

    data_sql = (
        f"SELECT * FROM ct_certs {where} "
        f"ORDER BY {sort_col} {sort_dir} "
        f"LIMIT {page_size} OFFSET {offset}"
    )
    try:
        rows = await db.fetch(data_sql, params, endpoint="list_certificates")
        print(rows)
        certs = []
        for r in rows:
            try:
                certs.append(_row_to_cert(r))
            except Exception as cert_exc:
                import logging
                logging.getLogger("api.certificates").exception(f"Failed to parse cert row: {r}\n{cert_exc}")
        total_pages = max(1, math.ceil(total / page_size))
        return CertificateListResponse(
            data=certs,
            meta=PaginationMeta(
                page=page,
                page_size=page_size,
                total=total,
                total_pages=total_pages,
            ),
        )
    except Exception as exc:
        import logging
        logging.getLogger("api.certificates").exception(f"list_certificates failed: {exc}")
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail="Internal Server Error")


# ---------------------------------------------------------------------------
# Search by fingerprint
# ---------------------------------------------------------------------------

@router.get(
    "/fingerprint/{sha256}",
    response_model=CertificateListResponse,
    summary="Find certificates by SHA-256 fingerprint",
)
async def find_by_fingerprint(sha256: str, db=Depends(_get_db)):
    rows = await db.fetch(
        "SELECT * FROM ct_certs WHERE fingerprint_sha256 = {fp:String} ORDER BY ts DESC",
        {"fp": sha256},
        endpoint="find_by_fingerprint",
    )
    certs = [_row_to_cert(r) for r in rows]
    return CertificateListResponse(
        data=certs,
        meta=PaginationMeta(
            page=1, page_size=len(certs), total=len(certs), total_pages=1
        ),
    )


# ---------------------------------------------------------------------------
# Search by DNS name
# ---------------------------------------------------------------------------
# TODO: FIX QUERY
@router.get(
    "/dns_name/{dns}",
    response_model=CertificateListResponse,
    summary="Find certificates by DNS names",
)
async def find_by_dns(dns: str, db=Depends(_get_db)):
    rows = await db.fetch(
        "SELECT * FROM ct_certs WHERE has(dns_names, {fp:String})",
        {"fp": dns},
        endpoint="find_by_dns"
    )
    print(rows)
    certs = [_row_to_cert(r) for r in rows]
    return CertificateListResponse(
        data=certs,
        meta=PaginationMeta(
            page=1, page_size=len(certs), total=len(certs), total_pages=1
        )
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_cert(row: dict) -> CertificateOut:
    dns_names = row.get("dns_names")
    if isinstance(dns_names, str):
        import json
        try:
            dns_names = json.loads(dns_names)
        except Exception:
            dns_names = [dns_names]
    elif dns_names is None:
        dns_names = []
    id_val = row.get("id", None)
    try:
        if id_val is not None:
            id_val = str(id_val)
    except Exception as e:
        import logging
        logging.getLogger("api.certificates").exception(f"Failed to convert id to string: {id_val} ({type(id_val)}) - {e}")
        id_val = None
    return CertificateOut(
        id=id_val,
        log=row.get("log", None),
        subject=row.get("subject", None),
        issuer=row.get("issuer", None),
        not_before=row.get("not_before", None),
        not_after=row.get("not_after", None),
        serial_number=row.get("serial_number", None),
        dns_names=dns_names,
        fingerprint_sha256=row.get("fingerprint_sha256", None),
        ts=row.get("ts", None),
        ct_entry_type=row.get("ct_entry_type", None),
        format=row.get("format", None),
    )