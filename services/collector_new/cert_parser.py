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

def parse_tile_data(
    tile_bytes: bytes,
    tile_index: int,
) -> "list[dict[str, Any]]":
    """
    Parse a full or partial data tile from a Static CT (tiled) log.

    tile_bytes  – raw bytes of the data tile
    tile_index  – 0-based tile number (tile N covers entries [N*256, …))

    Wire format is auto-detected from the first two bytes:
      0x00 0x00  → Sycamore/RFC-tlog (raw MerkleTreeLeaf TLS structs –
                   version=0 + leaf_type=0 is the first thing in the tile)
      anything else → Sunlight/Tuscolo (2-byte big-endian length prefix
                      per entry; that length is always > 0)

    Returns a list of parsed cert dicts (failures silently dropped).
    CPU-bound – call via asyncio.to_thread.
    """
    if _is_sunlight_format(tile_bytes):
        return _parse_tile_sunlight(tile_bytes, tile_index)
    else:
        return _parse_tile_sycamore(tile_bytes, tile_index)


def _is_sunlight_format(tile_bytes: bytes) -> bool:
    """
    Detect Sunlight/Tuscolo wire format vs Sycamore/RFC-tlog.

    Sycamore tiles always start with 0x00 0x00 (version=0 + leaf_type=0
    of the first MerkleTreeLeaf header).  A Sunlight 2-byte length prefix
    is always > 0, so it can never start with 0x00 0x00.
    """
    if len(tile_bytes) < 2:
        return False
    return not (tile_bytes[0] == 0x00 and tile_bytes[1] == 0x00)


def _parse_tile_sunlight(tile_bytes: bytes, tile_index: int) -> "list[dict[str, Any]]":
    """
    Sunlight/Tuscolo format: each entry is prefixed with a 2-byte big-endian
    length, followed by that many bytes of MerkleTreeLeaf (with the standard
    version+leaf_type header).
    """
    results  = []
    offset   = 0
    position = 0

    while offset + 2 <= len(tile_bytes):
        length = struct.unpack_from(">H", tile_bytes, offset)[0]
        offset += 2
        if offset + length > len(tile_bytes):
            break
        entry_bytes = tile_bytes[offset : offset + length]
        offset += length

        try:
            cert_dict = _parse_merkle_tree_leaf(entry_bytes, tile_index * TILE_SIZE + position)
            if cert_dict is not None:
                results.append(cert_dict)
        except Exception:
            pass
        position += 1

    return results


def _parse_tile_sycamore(tile_bytes: bytes, tile_index: int) -> "list[dict[str, Any]]":
    """
    Sycamore (Let's Encrypt) / static-ct-api format: raw concatenated
    MerkleTreeLeaf TLS structs with NO outer length prefix.  Each leaf
    starts with version(1) + leaf_type(1) + timestamp(8) + entry_type(2).
    """
    results  = []
    offset   = 0
    position = 0

    while offset < len(tile_bytes):
        try:
            cert_dict, consumed = _parse_sycamore_leaf(
                tile_bytes, offset,
                tile_index * TILE_SIZE + position,
            )
            if cert_dict is not None:
                results.append(cert_dict)
            offset   += consumed
            position += 1
        except Exception:
            # Cannot safely skip without a length prefix – stop this tile.
            break

    return results


# Internal constant – entries per full tile (fixed by spec)
TILE_SIZE = 256


def _parse_merkle_tree_leaf(data: bytes, index: int) -> "dict[str, Any] | None":
    """
    Parse a single MerkleTreeLeaf blob (Sunlight/Tuscolo per-entry bytes).

    Layout:
      [0]     version   (0x00)
      [1]     leaf_type (0x00 = timestamped_entry)
      [2:10]  timestamp (uint64 ms)
      [10:12] entry_type (uint16: 0=x509, 1=precert)
      … same as RFC 6962 leaf_input from here …
    """
    if len(data) < 12:
        return None
    # version + leaf_type must both be 0
    if data[0] != 0 or data[1] != 0:
        return None

    ts_ms      = struct.unpack_from(">Q", data, 2)[0]
    entry_type = struct.unpack_from(">H", data, 10)[0]
    offset     = 12

    if entry_type == X509_ENTRY:
        cert_len = _read_uint24(data, offset);  offset += 3
        cert_der = data[offset : offset + cert_len]
        cert     = _load_cert(cert_der)
        sha256   = hashlib.sha256(cert_der).hexdigest()
        ct_type  = "x509_entry"

    elif entry_type == PRECERT_ENTRY:
        offset  += 32  # skip issuer_key_hash
        tbs_len  = _read_uint24(data, offset);  offset += 3 + tbs_len

        # extensions (uint16 length-prefixed)
        if offset + 2 > len(data):
            return None
        ext_len = struct.unpack_from(">H", data, offset)[0];  offset += 2 + ext_len

        # For Sunlight precerts the original pre-certificate follows the extensions.
        # If the remaining bytes look like a DER SEQUENCE, parse them as the cert.
        remaining = data[offset:]
        if len(remaining) >= 4 and remaining[0] == 0x30:
            precert_der = remaining
        else:
            return None
        cert    = _load_cert(precert_der)
        sha256  = hashlib.sha256(precert_der).hexdigest()
        ct_type = "precert_entry"
    else:
        return None

    return _cert_to_dict(cert, index, ct_type, ts_ms, sha256)


def _parse_sycamore_leaf(
    buf: bytes,
    offset: int,
    index: int,
) -> "tuple[dict[str, Any] | None, int]":
    """
    Parse one MerkleTreeLeaf from the Sycamore raw-concatenated stream.

    Each leaf in the stream has the full RFC 6962 MerkleTreeLeaf header
    (version + leaf_type) followed by a TimestampedEntry.  For precerts the
    TBSCertificate is followed by a uint16-length extensions block, and then
    the original pre-certificate (DER, without a length prefix – it runs to
    the start of the next leaf's 0x00 0x00 header).

    Because there is no outer length prefix we detect the end of each entry
    by parsing the known-length fields precisely.

    Returns (cert_dict_or_None, bytes_consumed).
    """
    start = offset

    if offset + 12 > len(buf):
        raise ValueError("buffer too short for MerkleTreeLeaf header")

    # version + leaf_type (both 0x00)
    if buf[offset] != 0 or buf[offset + 1] != 0:
        raise ValueError(f"unexpected version/leaf_type bytes: {buf[offset]:#x} {buf[offset+1]:#x}")
    offset += 2

    ts_ms      = struct.unpack_from(">Q", buf, offset)[0];  offset += 8
    entry_type = struct.unpack_from(">H", buf, offset)[0];  offset += 2

    if entry_type == X509_ENTRY:
        if offset + 3 > len(buf):
            raise ValueError("buf too short for x509 cert_len")
        cert_len = _read_uint24(buf, offset);  offset += 3
        cert_der = buf[offset : offset + cert_len];  offset += cert_len

        # extensions (uint16)
        if offset + 2 > len(buf):
            raise ValueError("buf too short for extensions len")
        ext_len = struct.unpack_from(">H", buf, offset)[0];  offset += 2 + ext_len

        cert    = _load_cert(cert_der)
        sha256  = hashlib.sha256(cert_der).hexdigest()
        ct_type = "x509_entry"

    elif entry_type == PRECERT_ENTRY:
        if offset + 32 + 3 > len(buf):
            raise ValueError("buf too short for precert header")
        offset += 32                                         # skip issuer_key_hash
        tbs_len = _read_uint24(buf, offset);  offset += 3 + tbs_len  # skip TBSCert

        # extensions (uint16)
        if offset + 2 > len(buf):
            raise ValueError("buf too short for precert extensions")
        ext_len = struct.unpack_from(">H", buf, offset)[0];  offset += 2 + ext_len

        # The original pre-certificate runs from here until the next leaf's
        # 0x00 0x00 version+leaf_type header (or end of buffer).
        # Scan forward for the next 0x00 0x00 boundary.
        precert_start = offset
        precert_end   = _find_next_leaf_boundary(buf, offset)
        precert_der   = buf[precert_start:precert_end]
        offset        = precert_end

        cert    = _load_cert(precert_der)
        sha256  = hashlib.sha256(precert_der).hexdigest()
        ct_type = "precert_entry"

    else:
        raise ValueError(f"unknown entry_type {entry_type}")

    consumed = offset - start
    return _cert_to_dict(cert, index, ct_type, ts_ms, sha256), consumed


def _find_next_leaf_boundary(buf: bytes, start: int) -> int:
    """
    Find the offset of the next MerkleTreeLeaf start (0x00 0x00 header) after
    *start*, or return len(buf) if none is found.

    We look for 0x00 0x00 followed by an 8-byte timestamp (any value) and
    entry_type 0x00 or 0x01 – this is tight enough to avoid false positives
    inside DER data.
    """
    i = start
    while i + 12 <= len(buf):
        if buf[i] == 0x00 and buf[i + 1] == 0x00:
            entry_type = struct.unpack_from(">H", buf, i + 10)[0]
            if entry_type in (X509_ENTRY, PRECERT_ENTRY):
                return i
        i += 1
    return len(buf)


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