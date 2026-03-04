"""Certificate parsing and extraction from CT log Merkle tree leaves."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

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
        if entry_type != 0:
            return None

        cert_len = int.from_bytes(leaf[12:15], "big")
        cert_start = 15
        cert_end = cert_start + cert_len

        if cert_end > len(leaf):
            return None

        candidate = leaf[cert_start:cert_end]

        try:
            x509.load_der_x509_certificate(candidate, default_backend())
            return candidate
        except Exception:
            pass

        # Fallback: scan the leaf for a valid DER certificate using heuristics
        return CertificateParser._scan_for_der_cert(leaf)

    @staticmethod
    def extract_and_parse(leaf: bytes, log_url: str) -> Optional[dict]:
        """Extract the DER certificate from *leaf* and parse it in one step.

        Combines :meth:`extract_cert_from_leaf` and :meth:`parse`; returns
        the parsed metadata dict or ``None`` if either step fails.
        """
        der = CertificateParser.extract_cert_from_leaf(leaf)
        if der is None:
            return None
        return CertificateParser.parse(der, log_url)

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
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
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
            logger.exception(
                "Failed to parse certificate from %s: %s",
                log_url,
                exc,
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
        """Heuristic: scan for ASN.1 SEQUENCE tag."""
        for offset in range(12, len(leaf) - 4):
            if leaf[offset] == 0x30:
                try:
                    candidate = leaf[offset:]
                    x509.load_der_x509_certificate(
                        candidate, default_backend()
                    )
                    return candidate
                except Exception:
                    continue
        return None
