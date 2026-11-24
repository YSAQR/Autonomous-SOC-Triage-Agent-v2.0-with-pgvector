"""Read-only Threat Intelligence enrichment with PostgreSQL 24-hour TTL caching.

Security & Performance Guarantees:
- Strictly validates every IP with Python's `ipaddress` module before any external call.
- Skips private/RFC1918/loopback IPs completely (never persisted to `ioc_cache`).
- Enforces read-time 24-hour TTL check on `ioc_cache`.
- Runs AbuseIPDB, IP-API.com, and conditional OTX lookups concurrently with bounded
  4-second timeouts so slow external APIs never stall the SOC triage UI.
"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models import IoCCache

logger = get_logger(__name__)

_FAST_TI_TIMEOUT = 4.0


@dataclass(slots=True)
class EnrichedIoC:
    """Normalized Threat Intel record for a single public IP indicator."""

    ip_address: str
    abuse_confidence_score: int = 0
    total_reports: int = 0
    usage_type: str = "Unknown"
    country_code: str = "N/A"
    country_name: str = "Unknown"
    isp: str = "Unknown"
    asn: str = "Unknown"
    is_tor: bool = False
    otx_checked: bool = False
    otx_pulse_count: int = 0
    otx_tags: list[str] = field(default_factory=list)
    cache_status: str = "MISS"  # "HIT" | "MISS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "abuse_confidence_score": self.abuse_confidence_score,
            "total_reports": self.total_reports,
            "usage_type": self.usage_type,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "isp": self.isp,
            "asn": self.asn,
            "is_tor": self.is_tor,
            "otx_checked": self.otx_checked,
            "otx_pulse_count": self.otx_pulse_count,
            "otx_tags": self.otx_tags,
            "cache_status": self.cache_status,
        }


def is_public_ip(ip_str: str) -> bool:
    """Return True only if ip_str is a valid, globally routable (non-RFC1918) IP."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_global
    except ValueError:
        return False


class ThreatIntelService:
    """Read-only, PostgreSQL-cached Threat Intel lookup client."""

    def __init__(self, db: Session, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self._timeout = min(float(self.settings.http_timeout_seconds), _FAST_TI_TIMEOUT)

    def enrich_ips(self, ips: list[str], max_ips: int = 10) -> tuple[list[EnrichedIoC], int, int]:
        """Enrich public IPs using 24h Postgres cache -> concurrent AbuseIPDB + IP-API.com."""
        results: list[EnrichedIoC] = []
        cache_hits = 0
        cache_misses = 0
        misses_to_fetch: list[str] = []

        now = datetime.now(timezone.utc)
        for raw_ip in ips[:max_ips]:
            ip = raw_ip.strip()
            if not is_public_ip(ip):
                continue

            cached = self.db.get(IoCCache, ip)
            if cached is not None:
                expires = cached.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires > now:
                    cache_hits += 1
                    results.append(
                        EnrichedIoC(
                            ip_address=cached.ip_address,
                            abuse_confidence_score=cached.abuse_confidence_score,
                            total_reports=cached.total_reports,
                            usage_type=cached.usage_type,
                            country_code=cached.country_code,
                            country_name=cached.country_name,
                            isp=cached.isp,
                            asn=cached.asn,
                            is_tor=bool(cached.is_tor),
                            otx_checked=cached.otx_checked,
                            otx_pulse_count=cached.otx_pulse_count,
                            otx_tags=list(cached.otx_tags or []),
                            cache_status="HIT",
                        )
                    )
                    continue

            cache_misses += 1
            misses_to_fetch.append(ip)

        if misses_to_fetch:
            with ThreadPoolExecutor(max_workers=min(6, len(misses_to_fetch) * 2)) as pool:
                abuse_futs = {ip: pool.submit(self._fetch_abuseipdb, ip) for ip in misses_to_fetch}
                geo_futs = {ip: pool.submit(self._fetch_ip_api, ip) for ip in misses_to_fetch}

                for ip in misses_to_fetch:
                    abuse_data = abuse_futs[ip].result()
                    geo_data = geo_futs[ip].result()
                    enriched = EnrichedIoC(
                        ip_address=ip,
                        abuse_confidence_score=int(abuse_data.get("abuseConfidenceScore", 0)),
                        total_reports=int(abuse_data.get("totalReports", 0)),
                        usage_type=str(abuse_data.get("usageType") or "Unknown"),
                        country_code=str(
                            geo_data.get("countryCode") or abuse_data.get("countryCode") or "N/A"
                        ),
                        country_name=str(geo_data.get("country") or "Unknown"),
                        isp=str(geo_data.get("isp") or abuse_data.get("isp") or "Unknown"),
                        asn=str(geo_data.get("as") or "Unknown"),
                        is_tor=bool(abuse_data.get("isTor", False)),
                        otx_checked=False,
                        otx_pulse_count=0,
                        otx_tags=[],
                        cache_status="MISS",
                    )
                    self._upsert_cache(
                        enriched,
                        raw_payload={"abuseipdb": abuse_data, "ip_api": geo_data},
                    )
                    results.append(enriched)

        return results, cache_hits, cache_misses

    def enrich_with_otx(self, iocs: list[EnrichedIoC], max_otx_ips: int = 2) -> list[EnrichedIoC]:
        """Conditionally query AlienVault OTX in parallel (capped to max_otx_ips, 4s timeout)."""
        candidates = [
            ioc for ioc in iocs if is_public_ip(ioc.ip_address) and not ioc.otx_checked
        ][:max_otx_ips]

        if not candidates:
            return iocs

        with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
            otx_futs = {ioc.ip_address: pool.submit(self._fetch_otx, ioc.ip_address) for ioc in candidates}

            for ioc in candidates:
                otx_data = otx_futs[ioc.ip_address].result()
                pulse_info = otx_data.get("pulse_info", {}) if isinstance(otx_data, dict) else {}
                pulse_count = int(pulse_info.get("count", 0))
                pulses = pulse_info.get("pulses", []) or []
                tags: list[str] = []
                for pulse in pulses[:5]:
                    for tag in pulse.get("tags", [])[:4]:
                        if isinstance(tag, str) and tag not in tags:
                            tags.append(tag)

                ioc.otx_checked = True
                ioc.otx_pulse_count = pulse_count
                ioc.otx_tags = tags[:10]

                cached = self.db.get(IoCCache, ioc.ip_address)
                if cached is not None:
                    cached.otx_checked = True
                    cached.otx_pulse_count = pulse_count
                    cached.otx_tags = ioc.otx_tags
                    payload = dict(cached.raw_payload or {})
                    payload["otx"] = {"pulse_count": pulse_count, "tags": ioc.otx_tags}
                    cached.raw_payload = payload
                    self.db.commit()

        return iocs

    def _upsert_cache(self, ioc: EnrichedIoC, raw_payload: dict[str, Any]) -> None:
        """Persist or refresh a public IoC record with a 24-hour TTL."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=self.settings.ioc_cache_ttl_hours)

        existing = self.db.get(IoCCache, ioc.ip_address)
        if existing is None:
            record = IoCCache(
                ip_address=ioc.ip_address,
                abuse_confidence_score=ioc.abuse_confidence_score,
                total_reports=ioc.total_reports,
                usage_type=ioc.usage_type,
                country_code=ioc.country_code,
                country_name=ioc.country_name,
                isp=ioc.isp,
                asn=ioc.asn,
                is_tor=ioc.is_tor,
                otx_checked=ioc.otx_checked,
                otx_pulse_count=ioc.otx_pulse_count,
                otx_tags=ioc.otx_tags,
                raw_payload=raw_payload,
                cached_at=now,
                expires_at=expires_at,
            )
            self.db.add(record)
        else:
            existing.abuse_confidence_score = ioc.abuse_confidence_score
            existing.total_reports = ioc.total_reports
            existing.usage_type = ioc.usage_type
            existing.country_code = ioc.country_code
            existing.country_name = ioc.country_name
            existing.isp = ioc.isp
            existing.asn = ioc.asn
            existing.is_tor = ioc.is_tor
            existing.raw_payload = raw_payload
            existing.cached_at = now
            existing.expires_at = expires_at

        self.db.commit()

    def _fetch_abuseipdb(self, ip: str) -> dict[str, Any]:
        """Read-only GET to AbuseIPDB v2 check endpoint."""
        if not self.settings.abuseipdb_api_key:
            return {}
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Key": self.settings.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                )
                resp.raise_for_status()
                return resp.json().get("data", {})
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return {}

    def _fetch_ip_api(self, ip: str) -> dict[str, Any]:
        """Read-only GET to IP-API.com geolocation & ASN endpoint."""
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(
                    f"{self.settings.ip_api_base_url}/{ip}",
                    params={"fields": "status,country,countryCode,isp,as,query"},
                )
                resp.raise_for_status()
                data = resp.json()
                return data if data.get("status") == "success" else {}
        except Exception as exc:
            logger.warning("IP-API.com lookup failed for %s: %s", ip, exc)
            return {}

    def _fetch_otx(self, ip: str) -> dict[str, Any]:
        """Read-only GET to AlienVault OTX IPv4 general indicator endpoint."""
        if not self.settings.otx_api_key:
            return {}
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": self.settings.otx_api_key},
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.warning("AlienVault OTX lookup failed for %s: %s", ip, exc)
            return {}