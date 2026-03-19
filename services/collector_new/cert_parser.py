"""
cert_parser.py – Parse raw CT log entries into structured dicts.

Supports both RFC 6962 (non-tiled) and Static CT API (tiled) log formats.

═══════════════════════════════════════════════════════════════════════
RFC 6962  –  get-entries JSON response
═══════════════════════════════════════════════════════════════════════

Each JSON entry has two base64 fields:

  leaf_input  →  MerkleTreeLeaf (RFC 6962 §3.4)
  extra_data  →  chain data (varies by entry type)

MerkleTreeLeaf binary layout (all big-endian):
  [0]     version    (must be 0)
  [1]     leaf_type  (must be 0 = timestamped_entry)
  [2:10]  timestamp  (uint64, milliseconds since Unix epoch)
  [10:12] entry_type (uint16: 0 = x509_entry, 1 = precert_entry)

  if x509_entry:
    [12:15]  cert_len (uint24)
    [15:15+cert_len]  DER-encoded end-entity certificate

  if precert_entry:
    [12:44]  issuer_key_hash (32 bytes, SHA-256 of issuer SubjectPublicKeyInfo)
    [44:47]  tbs_len (uint24)
    [47:47+tbs_len]  DER-encoded TBSCertificate  ← stripped version (no poison)

extra_data for x509_entry:
    [0:3]   chain_list_len (uint24, total bytes of all certs that follow)
    for each cert:
      [0:3]  cert_len (uint24)
      [3:]   DER-encoded cert

extra_data for precert_entry  (PrecertChainEntry):
    [0:3]   precert_len (uint24)
    [3:]    DER-encoded PRE-CERTIFICATE (original, WITH poison extension)
    ← the full cert with poison; this is what we parse for SANs/subject
    followed by:
    [0:3]   chain_list_len (uint24)
    for each cert:
      [0:3]  cert_len (uint24)
      [3:]   DER-encoded cert

Key insight for precerts: the TBSCertificate in leaf_input is a STRIPPED
version (poison extension removed, issuer may be rewritten to the true
issuer).  The original precertificate in extra_data is a full, parseable
X.509 certificate that contains all the fields we care about (SANs, subject,
issuer, validity).  We parse from extra_data for precerts.

═══════════════════════════════════════════════════════════════════════
Static CT API (tiled logs)  –  data tile binary format
═══════════════════════════════════════════════════════════════════════

Data tiles live at:
  <monitoring_url>/tile/data/<N>           (full tile, 256 entries)
  <monitoring_url>/tile/data/<N>.p/<count> (partial tile, <count> entries)

A tile is a concatenation of TileLeaf records.  Each TileLeaf:

  TimestampedEntry  (same binary layout as in leaf_input above, identical
                     to RFC 6962 §3.4 – starts with the 8-byte timestamp,
                     NOT the version/leaf_type header bytes)

  if precert_entry:
    [0:3]   precert_len (uint24)
    [3:]    DER-encoded original PRE-CERTIFICATE (full cert with poison)

  Fingerprint certificate_chain<0..2^16-1>:
    [0:2]   chain_count×32 total length (uint16)
    [2:]    N×32 bytes of SHA-256 hashes of issuer certs

NOTE: Unlike RFC 6962 leaf_input, the tiled TimestampedEntry does NOT start
with the 2-byte version+leaf_type header.  It starts directly at the
timestamp field.  This is because TileLeaf embeds the TimestampedEntry
sub-structure directly (not the full MerkleTreeLeaf wrapper).
"""

import base64
import hashlib
import struct
import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# RFC 6962 entry type constants
X509_ENTRY    = 0
PRECERT_ENTRY = 1


# ═══════════════════════════════════════════════════════════════════════
# Public API – RFC 6962 (non-tiled)
# ═══════════════════════════════════════════════════════════════════════

def parse_entry(
    leaf_input_b64: str,
    extra_data_b64: str,
    index: int,
) -> "dict[str, Any] | None":
    """
    Parse one RFC 6962 CT log entry (from get-entries JSON).
    Returns a structured dict on success, None on any parse failure.
    Never raises.
    """
    try:
        leaf_bytes  = base64.b64decode(leaf_input_b64)
        extra_bytes = base64.b64decode(extra_data_b64)
        return _parse_rfc6962_leaf(leaf_bytes, extra_bytes, index)
    except Exception:
        return None


def parse_entries_bulk(
    entries: "list[dict]",
    start_index: int,
) -> "list[dict[str, Any]]":
    """
    Parse a list of raw entry dicts (as returned by get-entries JSON).
    Returns only successfully parsed entries; failures are silently dropped.
    CPU-bound – call via asyncio.to_thread.
    """
    results = []
    for i, entry in enumerate(entries):
        parsed = parse_entry(
            entry.get("leaf_input", ""),
            entry.get("extra_data", ""),
            start_index + i,
        )
        if parsed is not None:
            results.append(parsed)
    return results


# ═══════════════════════════════════════════════════════════════════════
# Public API – Static CT (tiled)
# ═══════════════════════════════════════════════════════════════════════

def parse_tile_data(tile_bytes: bytes, tile_index: int) -> "list[dict[str, Any]]":
    """
    Parse a full or partial data tile from a Static CT (tiled) log.

    tile_bytes  – raw bytes of the data tile (response body from
                  GET <monitoring_url>/tile/data/<N> or .p/<count>)
    tile_index  – 0-based tile number (tile N covers entries
                  [N*256, N*256 + count))

    Returns a list of parsed cert dicts (failures silently dropped).
    CPU-bound – call via asyncio.to_thread.
    """
    results  = []
    offset   = 0
    position = 0  # entry position within this tile

    while offset < len(tile_bytes):
        entry_start = offset
        try:
            cert_dict, consumed = _parse_tile_leaf(
                tile_bytes, offset,
                tile_index * 256 + position,
            )
            if cert_dict is not None:
                results.append(cert_dict)
            offset   += consumed
            position += 1
        except Exception:
            # Malformed entry – we cannot safely skip because TileLeaf
            # entries are not length-prefixed at the outer level.
            # Stop processing this tile.
            break

    return results


# ═══════════════════════════════════════════════════════════════════════
# RFC 6962 internals
# ═══════════════════════════════════════════════════════════════════════

def _parse_rfc6962_leaf(
    leaf: bytes,
    extra: bytes,
    index: int,
) -> "dict[str, Any]":
    """Decode a MerkleTreeLeaf + extra_data into a structured dict."""
    if len(leaf) < 12:
        raise ValueError("leaf_input too short")

    if leaf[0] != 0 or leaf[1] != 0:
        raise ValueError(f"unsupported version/leaf_type {leaf[0]}/{leaf[1]}")

    ts_ms      = struct.unpack_from(">Q", leaf, 2)[0]
    entry_type = struct.unpack_from(">H", leaf, 10)[0]
    offset     = 12

    if entry_type == X509_ENTRY:
        # leaf_input carries the full DER certificate
        cert_len = _read_uint24(leaf, offset)
        cert_der = leaf[offset + 3 : offset + 3 + cert_len]
        cert     = _load_cert(cert_der)
        sha256   = hashlib.sha256(cert_der).hexdigest()
        ct_type  = "x509_entry"

    elif entry_type == PRECERT_ENTRY:
        # leaf_input carries only the STRIPPED TBSCertificate (no poison).
        # extra_data carries the ORIGINAL full precertificate (with poison),
        # which is a valid X.509 cert and the one we parse for field values.
        #
        # PrecertChainEntry layout:
        #   uint24 precert_len
        #   [precert_len bytes] original precertificate DER
        #   uint24 chain_list_len
        #   … chain certs …
        if len(extra) < 3:
            raise ValueError("extra_data too short for precert")
        precert_len = _read_uint24(extra, 0)
        precert_der = extra[3 : 3 + precert_len]
        cert        = _load_cert(precert_der)
        sha256      = hashlib.sha256(precert_der).hexdigest()
        ct_type     = "precert_entry"

    else:
        raise ValueError(f"unknown entry_type {entry_type}")

    return _cert_to_dict(cert, index, ct_type, ts_ms, sha256)


# ═══════════════════════════════════════════════════════════════════════
# Tiled log internals
# ═══════════════════════════════════════════════════════════════════════

def _parse_tile_leaf(
    buf: bytes,
    offset: int,
    index: int,
) -> "tuple[dict[str, Any] | None, int]":
    """
    Parse one TileLeaf starting at buf[offset].

    Returns (cert_dict_or_None, bytes_consumed).

    TileLeaf structure (static-ct-api spec):
      TimestampedEntry timestamped_entry  ← starts at timestamp, NO version/leaf_type header
      if precert_entry:
        uint24 precert_len
        [precert_len] original precertificate DER
      uint16 fingerprint_list_len         ← total bytes = N × 32
      [fingerprint_list_len] SHA-256 hashes of issuer chain

    TimestampedEntry (no outer MerkleTreeLeaf wrapper):
      [0:8]   timestamp  (uint64 ms)
      [8:10]  entry_type (uint16)
      if x509_entry:
        [10:13]  cert_len (uint24)
        [13:]    DER certificate
      if precert_entry:
        [10:42]  issuer_key_hash (32 bytes)
        [42:45]  tbs_len (uint24)
        [45:]    TBSCertificate DER
    """
    start = offset

    if offset + 10 > len(buf):
        raise ValueError("buffer too short for TimestampedEntry header")

    ts_ms      = struct.unpack_from(">Q", buf, offset)[0]
    entry_type = struct.unpack_from(">H", buf, offset + 8)[0]
    offset    += 10

    if entry_type == X509_ENTRY:
        if offset + 3 > len(buf):
            raise ValueError("buffer too short for x509 cert_len")
        cert_len  = _read_uint24(buf, offset)
        offset   += 3
        cert_der  = buf[offset : offset + cert_len]
        offset   += cert_len
        cert      = _load_cert(cert_der)
        sha256    = hashlib.sha256(cert_der).hexdigest()
        ct_type   = "x509_entry"

    elif entry_type == PRECERT_ENTRY:
        # Skip issuer_key_hash (32 bytes) + TBSCertificate
        if offset + 32 + 3 > len(buf):
            raise ValueError("buffer too short for precert TBS header")
        offset   += 32  # skip issuer_key_hash
        tbs_len   = _read_uint24(buf, offset)
        offset   += 3 + tbs_len  # skip TBSCertificate

        # Read the original precertificate that follows (static-ct-api extension)
        if offset + 3 > len(buf):
            raise ValueError("buffer too short for precert_len")
        precert_len = _read_uint24(buf, offset)
        offset     += 3
        precert_der = buf[offset : offset + precert_len]
        offset     += precert_len

        cert    = _load_cert(precert_der)
        sha256  = hashlib.sha256(precert_der).hexdigest()
        ct_type = "precert_entry"

    else:
        raise ValueError(f"unknown entry_type {entry_type}")

    # Skip certificate_chain fingerprints (N × 32 bytes, prefixed by uint16 total length)
    if offset + 2 > len(buf):
        raise ValueError("buffer too short for fingerprint list length")
    chain_bytes_len  = struct.unpack_from(">H", buf, offset)[0]
    offset          += 2 + chain_bytes_len

    consumed = offset - start
    return _cert_to_dict(cert, index, ct_type, ts_ms, sha256), consumed


# ═══════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════

def _cert_to_dict(
    cert: "x509.Certificate",
    index: int,
    ct_type: str,
    ts_ms: int,
    sha256: str,
) -> "dict[str, Any]":
    """Build the output dict from a parsed x509.Certificate object."""
    dns_names  = _get_dns_names(cert)
    subject    = _rdns_to_str(cert.subject)
    issuer     = _rdns_to_str(cert.issuer)
    not_before = _cert_dt(cert, "not_valid_before")
    not_after  = _cert_dt(cert, "not_valid_after")

    return {
        "index":              index,
        "ct_entry_type":      ct_type,
        "timestamp_ms":       ts_ms,
        "subject":            subject,
        "issuer":             issuer,
        "not_before":         not_before.isoformat(),
        "not_after":          not_after.isoformat(),
        "serial_number":      format(cert.serial_number, "x"),
        "dns_names":          dns_names,
        "fingerprint_sha256": sha256,
    }


def _cert_dt(cert: "x509.Certificate", attr: str) -> datetime.datetime:
    """Get not_valid_before/after as a UTC-aware datetime, compat 36–42+."""
    utc_attr = attr + "_utc"
    if hasattr(cert, utc_attr):
        return getattr(cert, utc_attr)
    dt = getattr(cert, attr)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _read_uint24(buf: bytes, offset: int) -> int:
    return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]


def _load_cert(der: bytes) -> "x509.Certificate":
    """Load DER bytes as X.509, never raises (returns best-effort parse)."""
    try:
        return x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        # Occasionally a precert TBS blob is not a full cert; try wrapping.
        pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            + base64.b64encode(der)
            + b"\n-----END CERTIFICATE-----\n"
        )
        return x509.load_pem_x509_certificate(pem, default_backend())


def _rdns_to_str(name: "x509.Name") -> str:
    parts = []
    for attr in name:
        try:
            short = attr.oid._name if hasattr(attr.oid, "_name") else attr.oid.dotted_string
            parts.append(f"{short}={attr.value}")
        except Exception:
            pass
    return ", ".join(parts)


def _get_dns_names(cert: "x509.Certificate") -> "list[str]":
    """Extract DNS SANs, falling back to CN."""
    try:
        san   = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
        if names:
            return names
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return [cn[0].value]
    except Exception:
        pass

    return []