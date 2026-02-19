#!/usr/bin/env python3
# PCAP Sentry - Learn Malware Network Traffic Analysis (Beginner-Friendly Educational Tool)
# Copyright (C) 2026 retr0verride
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Threat Intelligence Integration Module for PCAP Sentry

Integrates with free/public threat intelligence sources:
- AlienVault OTX (Open Threat Exchange)
- AbuseIPDB (free tier)
- URLhaus
- Public DNS blacklists
"""

import contextlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Timeouts (connect, read) in seconds
_CONNECT_TIMEOUT = 2.0
_READ_TIMEOUT = 3.0
_REQUEST_TIMEOUT = (_CONNECT_TIMEOUT, _READ_TIMEOUT)

# Max concurrent network requests
_MAX_WORKERS = 6

# Maximum response size from external APIs (2 MB)
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# App-data paths for persistent cache and API usage counters
_CACHE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "PCAP_Sentry")
_CACHE_FILE = os.path.join(_CACHE_DIR, "ti_cache.json")
_USAGE_FILE = os.path.join(_CACHE_DIR, "api_usage.json")
_USAGE_LOCK = threading.Lock()


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _load_usage_data() -> dict:
    try:
        if os.path.exists(_USAGE_FILE):
            with open(_USAGE_FILE, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_usage_data(data: dict) -> None:
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        with open(_USAGE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def increment_api_usage(service: str) -> int:
    """Increment today's request counter for *service*. Returns the new daily count."""
    with _USAGE_LOCK:
        data = _load_usage_data()
        key = f"{service}_{_today()}"
        data[key] = data.get(key, 0) + 1
        _save_usage_data(data)
        return data[key]


def get_api_usage(service: str) -> int:
    """Return today's request count for *service* (0 if never used today)."""
    with _USAGE_LOCK:
        return _load_usage_data().get(f"{service}_{_today()}", 0)


class ThreatIntelligence:
    """Threat intelligence checker using free/public APIs"""

    def __init__(
        self,
        otx_api_key: str | None = None,
        abuseipdb_api_key: str | None = None,
        greynoise_api_key: str | None = None,
        virustotal_api_key: str | None = None,
    ):
        self.otx_base_url = "https://otx.alienvault.com/api/v1"
        self.otx_api_key = otx_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.greynoise_api_key = greynoise_api_key
        self.virustotal_api_key = virustotal_api_key
        self.abuseipdb_base_url = "https://api.abuseipdb.com/api/v2"
        self.greynoise_base_url = "https://api.greynoise.io/v3"
        self.virustotal_base_url = "https://www.virustotal.com/api/v3"
        self.urlhaus_base_url = "https://urlhaus-api.abuse.ch/v1"
        self._cache = {}  # Thread-safe cache to avoid repeated lookups
        self._cache_lock = threading.Lock()
        self.cache_ttl = 3600  # 1 hour
        self._max_cache_size = 500
        # Reusable HTTP session for connection pooling (keep-alive)
        self._session: requests.Session | None = None
        self._session_lock = threading.Lock()
        # Warm in-memory cache from the previous session's persisted data
        self._load_persistent_cache()

    def _get_session(self) -> "requests.Session":
        """Lazy-init a shared session for connection pooling."""
        if self._session is None:
            with self._session_lock:
                if self._session is None:
                    s = requests.Session()
                    s.headers.update({"Accept": "application/json"})
                    # Allow connection reuse across hosts
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=8,
                        pool_maxsize=12,
                        max_retries=0,
                    )
                    s.mount("https://", adapter)

                    # Block http:// to prevent accidental plaintext requests
                    # or redirect downgrades from HTTPS → HTTP.
                    class _BlockHTTPAdapter(requests.adapters.HTTPAdapter):
                        def send(self, *args, **kwargs):
                            raise ConnectionError("HTTP requests are blocked; use HTTPS only.")

                    s.mount("http://", _BlockHTTPAdapter())
                    self._session = s
        return self._session

    def close(self) -> None:
        """Close the HTTP session and persist the TI cache for the next session."""
        self._save_persistent_cache()
        with self._session_lock:
            if self._session is not None:
                with contextlib.suppress(Exception):
                    self._session.close()
                self._session = None

    def _load_persistent_cache(self) -> None:
        """Warm the in-memory TI cache from disk (survives app restarts within TTL)."""
        try:
            if os.path.exists(_CACHE_FILE):
                with open(_CACHE_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                now = time.time()
                with self._cache_lock:
                    for key, entry in data.items():
                        if isinstance(entry, list) and len(entry) == 2 and now - entry[1] < self.cache_ttl:
                            self._cache[key] = (entry[0], entry[1])
        except Exception:
            pass

    def _save_persistent_cache(self) -> None:
        """Write the current TI cache to disk for the next session."""
        try:
            os.makedirs(_CACHE_DIR, exist_ok=True)
            with self._cache_lock:
                data = {k: list(v) for k, v in self._cache.items()}
            with open(_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))
        except Exception:
            pass

    def is_available(self) -> bool:
        """Check if threat intelligence is available"""
        return REQUESTS_AVAILABLE

    def check_ip_reputation(self, ip: str) -> dict:
        """
        Check IP reputation using free public sources.
        Skips private/reserved IPs automatically.
        Returns dict with reputation data.
        """
        if not self.is_available():
            return {"available": False}

        if not self._is_routable_ip(ip):
            return {"valid": False}

        # Check cache first
        cache_key = f"ip:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = {"valid": True, "ip": ip, "sources": {}}

        # Run all available sources concurrently
        futures: dict = {}
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures["otx"] = pool.submit(self._check_otx_ip, ip)
            futures["abuseipdb"] = pool.submit(self._check_abuseipdb_ip, ip)
            futures["greynoise"] = pool.submit(self._check_greynoise_ip, ip)
            futures["virustotal"] = pool.submit(self._check_virustotal_ip, ip)
            futures["threatfox"] = pool.submit(self._check_threatfox_ip, ip)

        for source, future in futures.items():
            data = future.result()
            if data:
                result["sources"][source] = data

        # Calculate overall risk score
        result["risk_score"] = self._calculate_ip_risk(result["sources"])

        # Cache the result
        self._cache_put(cache_key, result)
        return result

    def _cache_get(self, key: str):
        """Thread-safe cache read with TTL expiry."""
        with self._cache_lock:
            if key in self._cache:
                data, timestamp = self._cache[key]
                if time.time() - timestamp < self.cache_ttl:
                    return data
                del self._cache[key]
        return None

    def _cache_put(self, key: str, value):
        """Thread-safe cache write with size eviction."""
        now = time.time()
        with self._cache_lock:
            # Evict expired entries if cache is at capacity
            if len(self._cache) >= self._max_cache_size:
                expired = [k for k, (_, ts) in self._cache.items() if now - ts >= self.cache_ttl]
                for k in expired:
                    del self._cache[k]
                # If still full, remove oldest entry
                if len(self._cache) >= self._max_cache_size:
                    oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                    del self._cache[oldest_key]
            self._cache[key] = (value, now)

    def _safe_json(self, response) -> dict:
        """Parse JSON from a requests response with a size limit to prevent OOM."""
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Response too large: {content_length} bytes")
        raw = response.content
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Response too large: {len(raw)} bytes")
        return response.json()

    def check_domain_reputation(self, domain: str) -> dict:
        """
        Check domain reputation using free public sources
        """
        if not self.is_available():
            return {"available": False}

        # Basic domain validation
        if not domain or len(domain) > 253 or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$", domain):
            return {"valid": False}
        # Enforce per-label max length (RFC 1035)
        if any(len(label) > 63 for label in domain.split(".")):
            return {"valid": False}

        cache_key = f"domain:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = {"domain": domain, "sources": {}}

        # Run all available sources concurrently
        futures: dict = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures["otx"] = pool.submit(self._check_otx_domain, domain)
            futures["urlhaus"] = pool.submit(self._check_urlhaus, domain)
            futures["virustotal"] = pool.submit(self._check_virustotal_domain, domain)
            futures["threatfox"] = pool.submit(self._check_threatfox_domain, domain)

        for source, future in futures.items():
            data = future.result()
            if data:
                result["sources"][source] = data

        # Calculate overall risk score
        result["risk_score"] = self._calculate_domain_risk(result["sources"])

        self._cache_put(cache_key, result)
        return result

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_routable_ip(self, ip: str) -> bool:
        """Check that IP is a valid, globally-routable address worth querying."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # Skip private, loopback, link-local, multicast, reserved, etc.
        return addr.is_global

    def _check_otx_ip(self, ip: str) -> dict | None:
        """Check IP against AlienVault OTX (free, API key optional for enhanced data)"""
        try:
            safe_ip = urllib.parse.quote(ip, safe="")
            url = f"{self.otx_base_url}/indicators/IPv4/{safe_ip}/general"
            headers = {}
            if self.otx_api_key:
                headers["X-OTX-API-KEY"] = self.otx_api_key

            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 200:
                data = self._safe_json(response)
                result = {}

                # Basic reputation data
                if data.get("reputation"):
                    result["reputation"] = data["reputation"]

                # Pulse count and tags
                if data.get("pulse_info"):
                    pulse_info = data["pulse_info"]
                    result["pulse_count"] = pulse_info.get("count", 0)

                    # With API key, get detailed pulse information
                    if self.otx_api_key and pulse_info.get("pulses"):
                        pulses = pulse_info["pulses"][:3]  # Top 3 pulses
                        result["pulses"] = [
                            {
                                "name": p.get("name"),
                                "tags": p.get("tags", [])[:5],  # Top 5 tags
                                "malware_families": p.get("malware_families", [])[:3],
                                "attack_ids": p.get("attack_ids", [])[:3],
                            }
                            for p in pulses
                        ]

                # Additional metadata
                if data.get("alexa"):
                    result["alexa_rank"] = data["alexa"]
                if data.get("country_name"):
                    result["country"] = data["country_name"]

                return result if result else None
            return None
        except Exception as e:
            print(f"[DEBUG] OTX IP check failed: {e}")
            return None

    def _check_otx_domain(self, domain: str) -> dict | None:
        """Check domain against AlienVault OTX (API key optional for enhanced data)"""
        try:
            safe_domain = urllib.parse.quote(domain, safe="")
            url = f"{self.otx_base_url}/indicators/domain/{safe_domain}/general"
            headers = {}
            if self.otx_api_key:
                headers["X-OTX-API-KEY"] = self.otx_api_key

            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 200:
                data = self._safe_json(response)
                result = {}

                # Basic reputation data
                if data.get("reputation"):
                    result["reputation"] = data["reputation"]

                # Pulse count and tags
                if data.get("pulse_info"):
                    pulse_info = data["pulse_info"]
                    result["pulse_count"] = pulse_info.get("count", 0)

                    # With API key, get detailed pulse information
                    if self.otx_api_key and pulse_info.get("pulses"):
                        pulses = pulse_info["pulses"][:3]  # Top 3 pulses
                        result["pulses"] = [
                            {
                                "name": p.get("name"),
                                "tags": p.get("tags", [])[:5],
                                "malware_families": p.get("malware_families", [])[:3],
                            }
                            for p in pulses
                        ]

                # Additional metadata
                if data.get("alexa"):
                    result["alexa_rank"] = data["alexa"]
                if data.get("whois"):
                    result["whois"] = data["whois"]

                return result if result else None
            return None
        except Exception as e:
            print(f"[DEBUG] OTX domain check failed: {e}")
            return None

    def _check_abuseipdb_ip(self, ip: str) -> dict | None:
        """Check IP against AbuseIPDB (requires API key for detailed data)."""
        if not self.abuseipdb_api_key:
            return None
        try:
            safe_ip = urllib.parse.quote(ip, safe="")
            url = f"{self.abuseipdb_base_url}/check"
            headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
            params = {"ipAddress": safe_ip, "maxAgeInDays": "90", "verbose": ""}
            response = self._get_session().get(url, headers=headers, params=params, timeout=_REQUEST_TIMEOUT)
            if response.status_code == 200:
                increment_api_usage("abuseipdb")
                data = self._safe_json(response).get("data", {})
                result: dict = {}
                confidence = data.get("abuseConfidenceScore")
                if confidence is not None:
                    result["confidence"] = confidence
                total = data.get("totalReports")
                if total is not None:
                    result["total_reports"] = total
                country = data.get("countryCode")
                if country:
                    result["country"] = country
                return result if result else None
            return None
        except Exception as e:
            print(f"[DEBUG] AbuseIPDB check failed: {e}")
            return None

    def _check_greynoise_ip(self, ip: str) -> dict | None:
        """Check IP against GreyNoise Community API.

        Works without a key (anonymous, lower rate limit); providing a key
        lifts the rate limit and may return richer classification data.
        """
        try:
            safe_ip = urllib.parse.quote(ip, safe="")
            url = f"{self.greynoise_base_url}/community/{safe_ip}"
            headers: dict[str, str] = {}
            if self.greynoise_api_key:
                headers["key"] = self.greynoise_api_key
            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
            if response.status_code == 200:
                data = self._safe_json(response)
                result: dict = {}
                noise = data.get("noise")
                if noise is not None:
                    result["noise"] = noise  # True = internet background scanner
                riot = data.get("riot")
                if riot is not None:
                    result["riot"] = riot  # True = benign (CDN, DNS, etc.)
                classification = data.get("classification")
                if classification:
                    result["classification"] = classification  # 'malicious', 'benign', 'unknown'
                name = data.get("name")
                if name:
                    result["name"] = name
                return result if result else None
            return None
        except Exception as e:
            print(f"[DEBUG] GreyNoise check failed: {e}")
            return None

    def _check_virustotal_ip(self, ip: str) -> dict | None:
        """Check IP against VirusTotal (requires API key, 500 req/day free)."""
        if not self.virustotal_api_key:
            return None
        try:
            safe_ip = urllib.parse.quote(ip, safe="")
            url = f"{self.virustotal_base_url}/ip_addresses/{safe_ip}"
            headers = {"x-apikey": self.virustotal_api_key}
            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
            if response.status_code == 200:
                increment_api_usage("virustotal")
                stats = self._safe_json(response).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats:
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
            return None
        except Exception as e:
            print(f"[DEBUG] VirusTotal IP check failed: {e}")
            return None

    def _check_virustotal_domain(self, domain: str) -> dict | None:
        """Check domain against VirusTotal (requires API key, 500 req/day free)."""
        if not self.virustotal_api_key:
            return None
        try:
            safe_domain = urllib.parse.quote(domain, safe="")
            url = f"{self.virustotal_base_url}/domains/{safe_domain}"
            headers = {"x-apikey": self.virustotal_api_key}
            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
            if response.status_code == 200:
                increment_api_usage("virustotal")
                stats = self._safe_json(response).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats:
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
            return None
        except Exception as e:
            print(f"[DEBUG] VirusTotal domain check failed: {e}")
            return None

    def _check_threatfox_ip(self, ip: str) -> dict | None:
        """Check IP against ThreatFox (abuse.ch) C2 tracker — no API key required."""
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            payload = {"query": "search_ioc", "search_term": ip}
            response = self._get_session().post(url, json=payload, timeout=_REQUEST_TIMEOUT)
            if response.status_code == 200:
                data = self._safe_json(response)
                if data.get("query_status") == "ok" and data.get("data"):
                    iocs = data["data"][:5]
                    return {
                        "found": True,
                        "count": len(iocs),
                        "malware": list({ioc.get("malware_printable") for ioc in iocs if ioc.get("malware_printable")})[
                            :3
                        ],
                        "threat_types": list({ioc.get("threat_type") for ioc in iocs if ioc.get("threat_type")})[:3],
                        "confidence": max((ioc.get("confidence_level") or 0) for ioc in iocs),
                    }
                if data.get("query_status") in ("ok", "no_result"):
                    return {"found": False}
            return None
        except Exception as e:
            print(f"[DEBUG] ThreatFox IP check failed: {e}")
            return None

    def _check_threatfox_domain(self, domain: str) -> dict | None:
        """Check domain against ThreatFox (abuse.ch) C2 tracker — no API key required."""
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            payload = {"query": "search_ioc", "search_term": domain}
            response = self._get_session().post(url, json=payload, timeout=_REQUEST_TIMEOUT)
            if response.status_code == 200:
                data = self._safe_json(response)
                if data.get("query_status") == "ok" and data.get("data"):
                    iocs = data["data"][:5]
                    return {
                        "found": True,
                        "count": len(iocs),
                        "malware": list({ioc.get("malware_printable") for ioc in iocs if ioc.get("malware_printable")})[
                            :3
                        ],
                        "confidence": max((ioc.get("confidence_level") or 0) for ioc in iocs),
                    }
                if data.get("query_status") in ("ok", "no_result"):
                    return {"found": False}
            return None
        except Exception as e:
            print(f"[DEBUG] ThreatFox domain check failed: {e}")
            return None

    def _check_urlhaus(self, domain: str) -> dict | None:
        """Check domain against URLhaus malware URL database"""
        try:
            url = f"{self.urlhaus_base_url}/host/"
            data = {"host": domain}
            response = self._get_session().post(url, data=data, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 200:
                result = self._safe_json(response)
                if result.get("query_status") == "ok" and result.get("urls"):
                    return {
                        "found": True,
                        "url_count": len(result["urls"]),
                        "urls": [{"url": u["url"], "threat": u.get("threat")} for u in result["urls"][:5]],
                    }
                if result.get("query_status") == "ok":
                    return {"found": False}
            return None
        except Exception as e:
            print(f"[DEBUG] URLhaus check failed: {e}")
            return None

    def _calculate_ip_risk(self, sources: dict) -> float:
        """Calculate overall IP risk score (0-100) from all available sources."""
        risk_score = 0.0

        if "otx" in sources:
            otx_rep = sources["otx"].get("reputation", 0)
            if isinstance(otx_rep, dict):
                otx_rep = otx_rep.get("threat_score", 0) or 0
            if otx_rep:
                risk_score = max(risk_score, min(float(otx_rep) * 10, 100.0))
            # Pulse presence is a strong indicator
            if sources["otx"].get("pulse_count", 0) > 0:
                risk_score = max(risk_score, 40.0)

        if "abuseipdb" in sources:
            confidence = sources["abuseipdb"].get("confidence", 0)
            if isinstance(confidence, (int, float)) and confidence > 0:
                risk_score = max(risk_score, float(confidence))

        if "greynoise" in sources:
            gn = sources["greynoise"]
            if gn.get("classification") == "malicious":
                risk_score = max(risk_score, 80.0)
            elif gn.get("riot"):
                # Benign service (CDN, DNS resolver, etc.) — lower score
                risk_score = min(risk_score, 10.0)

        if "virustotal" in sources:
            vt = sources["virustotal"]
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            if malicious >= 5:
                risk_score = max(risk_score, 85.0)
            elif malicious > 0:
                risk_score = max(risk_score, 40.0 + malicious * 5)
            elif suspicious > 0:
                risk_score = max(risk_score, 25.0)

        if "threatfox" in sources and sources["threatfox"].get("found"):
            confidence = sources["threatfox"].get("confidence", 0)
            # ThreatFox confidence 0-100; map to risk 50-95
            risk_score = max(risk_score, 50.0 + confidence * 0.45)

        return min(100.0, risk_score)

    def _calculate_domain_risk(self, sources: dict) -> float:
        """Calculate overall domain risk score (0-100) from all available sources."""
        risk_score = 0.0

        if "otx" in sources:
            otx_rep = sources["otx"].get("reputation", 0)
            if isinstance(otx_rep, dict):
                otx_rep = otx_rep.get("threat_score", 0) or 0
            if otx_rep:
                risk_score = max(risk_score, min(float(otx_rep) * 10, 100.0))
            if sources["otx"].get("pulse_count", 0) > 0:
                risk_score = max(risk_score, 40.0)

        if "urlhaus" in sources and sources["urlhaus"].get("found"):
            risk_score = max(risk_score, 75.0)  # High risk if found in URLhaus

        if "virustotal" in sources:
            vt = sources["virustotal"]
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)
            if malicious >= 5:
                risk_score = max(risk_score, 85.0)
            elif malicious > 0:
                risk_score = max(risk_score, 40.0 + malicious * 5)
            elif suspicious > 0:
                risk_score = max(risk_score, 25.0)

        if "threatfox" in sources and sources["threatfox"].get("found"):
            confidence = sources["threatfox"].get("confidence", 0)
            risk_score = max(risk_score, 50.0 + confidence * 0.45)

        return min(100.0, risk_score)

    def enrich_stats(self, stats: dict, progress_cb=None) -> dict:
        """
        Enrich analysis statistics with threat intelligence.
        progress_cb(fraction) is called with 0.0-1.0 to report progress.

        All IP and domain lookups run concurrently for speed.
        Private/bogon IPs are automatically skipped.
        """
        if not self.is_available():
            return stats

        enriched = stats.copy()
        enriched["threat_intel"] = {}

        t0 = time.time()

        # ── Collect work items ──
        all_ips = set(stats.get("unique_src_list", []))
        all_ips.update(stats.get("unique_dst_list", []))
        # Pre-filter: skip private/bogon IPs before submitting work
        ip_list = [ip for ip in list(all_ips)[:20] if self._is_routable_ip(ip)]

        domains: set = set()
        domains.update(stats.get("dns_queries", []))
        domains.update(stats.get("http_hosts", []))
        domains.update(stats.get("tls_sni", []))
        domain_list = list(domains)[:20]

        total_items = len(ip_list) + len(domain_list)
        if total_items == 0:
            if progress_cb:
                progress_cb(1.0)
            return enriched

        completed = 0
        progress_lock = threading.Lock()

        def _advance_progress():
            nonlocal completed
            with progress_lock:
                completed += 1
                if progress_cb and total_items:
                    progress_cb(completed / total_items)

        # ── Concurrent lookups ──
        ip_risks: list[dict] = []
        domain_risks: list[dict] = []
        results_lock = threading.Lock()

        def _check_ip(ip):
            try:
                rep = self.check_ip_reputation(ip)
                if rep.get("risk_score", 0) > 30:
                    with results_lock:
                        ip_risks.append(
                            {
                                "ip": ip,
                                "risk_score": rep["risk_score"],
                                "sources": rep["sources"],
                            }
                        )
            except Exception as e:
                print(f"[DEBUG] Error enriching IP {ip}: {e}")
            finally:
                _advance_progress()

        def _check_domain(domain):
            try:
                rep = self.check_domain_reputation(domain)
                if rep.get("risk_score", 0) > 30:
                    with results_lock:
                        domain_risks.append(
                            {
                                "domain": domain,
                                "risk_score": rep["risk_score"],
                                "sources": rep["sources"],
                            }
                        )
            except Exception as e:
                print(f"[DEBUG] Error enriching domain {domain}: {e}")
            finally:
                _advance_progress()

        workers = min(_MAX_WORKERS, total_items)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_check_ip, ip) for ip in ip_list]
            futures.extend(pool.submit(_check_domain, domain) for domain in domain_list)
            # Wait for all to finish
            for _f in as_completed(futures):
                pass  # exceptions already handled inside workers

        if ip_risks:
            enriched["threat_intel"]["risky_ips"] = sorted(
                ip_risks,
                key=lambda x: x["risk_score"],
                reverse=True,
            )
        if domain_risks:
            enriched["threat_intel"]["risky_domains"] = sorted(
                domain_risks,
                key=lambda x: x["risk_score"],
                reverse=True,
            )

        elapsed = time.time() - t0
        print(
            f"[TIMING] Threat intel enrichment: {elapsed:.2f}s "
            f"({len(ip_list)} IPs, {len(domain_list)} domains, "
            f"{workers} workers)"
        )

        return enriched


def check_online_reputation(ip: str | None = None, domain: str | None = None) -> dict:
    """
    Convenience function to check reputation of IP or domain
    """
    ti = ThreatIntelligence()
    result = {}

    if ip:
        result["ip"] = ti.check_ip_reputation(ip)
    if domain:
        result["domain"] = ti.check_domain_reputation(domain)

    return result


if __name__ == "__main__":
    # Test the module
    if REQUESTS_AVAILABLE:
        ti = ThreatIntelligence()

        # Test IP check
        print("Testing IP reputation check...")
        ip_result = ti.check_ip_reputation("8.8.8.8")
        print(json.dumps(ip_result, indent=2))

        # Test domain check
        print("\nTesting domain reputation check...")
        domain_result = ti.check_domain_reputation("google.com")
        print(json.dumps(domain_result, indent=2))
    else:
        print("requests library not available. Install with: pip install requests")
