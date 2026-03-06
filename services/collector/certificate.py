"""Certificate parsing and extraction from CT log Merkle tree leaves."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base64

from .config import get_logger

logger = get_logger("CTStreamService.Certificate")


class CertificateParser:
    """Extract and parse DER certs from Merkle leaves."""

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_cert_from_leaf(leaf: bytes) -> Optional[bytes]:
        """Extract the DER certificate from a MerkleTreeLeaf for X.509 entries.

        Returns the raw DER bytes or ``None`` if extraction fails.
        """
        if len(leaf) < 15:
            return None

        # RFC 6962 MerkleTreeLeaf layout:
        #   version     (1 byte)  offset 0
        #   leaf_type   (1 byte)  offset 1
        #   timestamp   (8 bytes) offset 2
        #   entry_type  (2 bytes) offset 10
        #   [X509 entry]: cert_length (3 bytes, uint24) + cert DER
        entry_type = int.from_bytes(leaf[10:12], "big")

        # If this is a standard X.509 entry, the cert length is encoded
        # directly after the header. For precert entries the cert may not
        # be present in the same layout, so fall back to a heuristic scan.
        if entry_type == 0:
            #PRE CERTS
            cert_len = int.from_bytes(leaf[12:15], "big")
            cert_start = 15
            cert_end = cert_start + cert_len

            if cert_end <= len(leaf):
                candidate = leaf[cert_start:cert_end]
                try:
                    x509.load_der_x509_certificate(candidate, default_backend())
                    return candidate
                except Exception:
                    pass

        # For precerts or when the explicit length/DER block isn't valid,
        # attempt a heuristic scan of the leaf for a DER-encoded cert.
        return CertificateParser._scan_for_der_cert(leaf)

    @staticmethod
    def extract_and_parse(leaf: bytes, log_url: str, entry_type: int | None = None) -> Optional[dict]:
        """Extract the DER certificate from *leaf* and parse it in one step.

        Combines :meth:`extract_cert_from_leaf` and :meth:`parse`; returns
        the parsed metadata dict or ``None`` if either step fails.
        """
        der = CertificateParser.extract_cert_from_leaf(leaf)
        if der is None:
            return None

        parsed = CertificateParser.parse(der, log_url)
        if parsed is None:
            return None

        # Annotate the parsed metadata with CT entry type information so
        # downstream systems (DB, Web UI) can display whether this came
        # from an X.509 entry or a Precertificate entry.
        et = entry_type
        if et is None:
            hdr = CertificateParser.parse_leaf_header(leaf)
            et = hdr[2] if hdr is not None else None

        if et == 1:
            parsed["ct_entry_type"] = "precert"
        else:
            parsed["ct_entry_type"] = "x509"

        parsed["format"] = "der"
        return parsed

    @staticmethod
    def parse_leaf_header(leaf: bytes):
        """Return ``(leaf_version, leaf_type, entry_type)`` or ``None``."""
        if len(leaf) < 12:
            return None
        return leaf[0], leaf[1], int.from_bytes(leaf[10:12], "big")

    @staticmethod
    def parse(der_bytes: bytes, log_url: str) -> Optional[dict]:
        """Parse a DER-encoded certificate into a metadata dictionary."""
        try:
            # Primary attempt: load as a DER X.509 certificate
            try:
                cert = x509.load_der_x509_certificate(der_bytes, default_backend())
            except Exception as primary_exc:
                # Secondary fallback: try to locate an embedded DER X.509
                # SEQUENCE inside the provided blob by scanning for ASN.1
                # SEQUENCE tags and using the length bytes to extract a
                # well-formed candidate. This helps when callers hand us a
                # wrapper structure or extra_data that isn't a pure cert.
                candidate = CertificateParser._find_embedded_der(der_bytes)
                if candidate is not None:
                    try:
                        cert = x509.load_der_x509_certificate(candidate, default_backend())
                    except Exception:
                        cert = None

                # If scanning didn't help, try PKCS7/CMS extraction as a
                # last resort before failing.
                if 'cert' not in locals() or cert is None:
                    try:
                        from cryptography.hazmat.primitives.serialization import pkcs7

                        certs = pkcs7.load_der_pkcs7_certificates(der_bytes)
                        if certs and len(certs) > 0:
                            cert = certs[0]
                        else:
                            raise primary_exc
                    except Exception:
                        # Re-raise the original error path to be caught by
                        # outer handler below for unified logging.
                        raise primary_exc
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()

            logger.debug(
                "Parsed cert from %s: subject=%s issuer=%s serial=%s",
                log_url,
                subject,
                issuer,
                cert.serial_number,
            )

            dns_names = CertificateParser._get_dns_names(cert)
            fingerprint = CertificateParser._get_fingerprint(cert)

            not_before = (
                cert.not_valid_before_utc.isoformat()
                if hasattr(cert, "not_valid_before_utc")
                else cert.not_valid_before.isoformat()
            )
            not_after = (
                cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after.isoformat()
            )

            return {
                "log": log_url,
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "serial_number": str(cert.serial_number),
                "dns_names": dns_names,
                "fingerprint_sha256": fingerprint,
                "version": (
                    cert.version.name
                    if hasattr(cert, "version")
                    else "unknown"
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            # Log the error (with traceback) and include a short base64
            # prefix for debugging the blob contents that failed to parse.
            try:
                preview = base64.b64encode(der_bytes)[:160].decode('ascii')
            except Exception:
                preview = None
            logger.exception(
                "Failed to parse certificate from %s: %s",
                log_url,
                exc,
            )
            logger.debug(
                "DER parse preview (base64 prefix): %s", preview
            )
            return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_dns_names(cert) -> list[str]:
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            return san.value.get_values_for_type(x509.DNSName)
        except Exception:
            return []

    @staticmethod
    def _get_fingerprint(cert) -> str:
        try:
            return cert.fingerprint(cert.signature_hash_algorithm).hex()
        except Exception:
            return cert.fingerprint(hashes.SHA256()).hex()

    @staticmethod
    def _scan_for_der_cert(leaf: bytes) -> Optional[bytes]:
        """Heuristic: scan for ASN.1 SEQUENCE tag and extract definite-length block."""
        for offset in range(12, len(leaf) - 4):
            if leaf[offset] == 0x30:
                candidate = CertificateParser._extract_der_block_at_offset(leaf, offset)
                if candidate is None:
                    continue
                try:
                    x509.load_der_x509_certificate(candidate, default_backend())
                    return candidate
                except Exception:
                    continue
        return None

    @staticmethod
    def _extract_der_block_at_offset(buf: bytes, offset: int) -> Optional[bytes]:
        """Given a buffer and an offset at which a 0x30 SEQUENCE tag was
        found, parse the ASN.1 length bytes and return the exact DER slice
        for the sequence if it fits inside the buffer. Returns None on
        any parse problem.
        """
        # Need at least tag + one length byte
        if offset + 2 > len(buf):
            return None
        # length byte
        try:
            lb = buf[offset + 1]
        except Exception:
            return None

        # Short form
        if lb & 0x80 == 0:
            length = lb
            len_of_len = 1
        else:
            num_bytes = lb & 0x7F
            if num_bytes == 0 or num_bytes > 4:
                return None
            if offset + 2 + num_bytes > len(buf):
                return None
            length = 0
            for i in range(num_bytes):
                length = (length << 8) | buf[offset + 2 + i]
            len_of_len = 1 + num_bytes

        total_len = 1 + len_of_len + length
        end = offset + total_len
        if end <= len(buf):
            return buf[offset:end]
        return None

    @staticmethod
    def _find_embedded_der(buf: bytes) -> Optional[bytes]:
        """Scan buffer for an embedded DER SEQUENCE and return the first
        valid candidate slice, or None if none found.
        """
        for off in range(0, len(buf) - 4):
            if buf[off] == 0x30:
                candidate = CertificateParser._extract_der_block_at_offset(buf, off)
                if candidate is None:
                    continue
                try:
                    x509.load_der_x509_certificate(candidate, default_backend())
                    return candidate
                except Exception:
                    continue
        return None
