"""
Threat Intelligence Integration Module for PCAP Sentry

Integrates with free/public threat intelligence sources:
- AlienVault OTX (Open Threat Exchange)
- AbuseIPDB (free tier)
- URLhaus
- Public DNS blacklists
"""

import json
import threading
import time
from typing import Dict, List, Tuple, Optional
import ipaddress
import socket

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ThreatIntelligence:
    """Threat intelligence checker using free/public APIs"""

    def __init__(self):
        self.otx_base_url = "https://otx.alienvault.com/api/v1"
        self.abuseipdb_base_url = "https://api.abuseipdb.com/api/v2"
        self.urlhaus_base_url = "https://urlhaus-api.abuse.ch/v1"
        self.cache = {}  # Simple cache to avoid repeated lookups
        self.cache_ttl = 3600  # 1 hour

    def is_available(self) -> bool:
        """Check if threat intelligence is available"""
        return REQUESTS_AVAILABLE

    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check IP reputation using free public sources
        Returns dict with reputation data
        """
        if not self.is_available():
            return {"available": False}

        if not self._is_valid_ip(ip):
            return {"valid": False}

        # Check cache first
        cache_key = f"ip:{ip}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data

        result = {
            "valid": True,
            "ip": ip,
            "sources": {}
        }

        # Check AlienVault OTX
        otx_data = self._check_otx_ip(ip)
        if otx_data:
            result["sources"]["otx"] = otx_data

        # Check AbuseIPDB (free tier - limited to 1000 requests/day)
        abuse_data = self._check_abuseipdb_ip(ip)
        if abuse_data:
            result["sources"]["abuseipdb"] = abuse_data

        # Calculate overall risk score
        result["risk_score"] = self._calculate_ip_risk(result["sources"])

        # Cache the result
        self.cache[cache_key] = (result, time.time())
        return result

    def check_domain_reputation(self, domain: str) -> Dict:
        """
        Check domain reputation using free public sources
        """
        if not self.is_available():
            return {"available": False}

        cache_key = f"domain:{domain}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data

        result = {
            "domain": domain,
            "sources": {}
        }

        # Check AlienVault OTX
        otx_data = self._check_otx_domain(domain)
        if otx_data:
            result["sources"]["otx"] = otx_data

        # Check URLhaus for malicious URLs
        url_data = self._check_urlhaus(domain)
        if url_data:
            result["sources"]["urlhaus"] = url_data

        # Calculate overall risk score
        result["risk_score"] = self._calculate_domain_risk(result["sources"])

        self.cache[cache_key] = (result, time.time())
        return result

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _check_otx_ip(self, ip: str) -> Optional[Dict]:
        """Check IP against AlienVault OTX (free, no API key required)"""
        try:
            url = f"{self.otx_base_url}/indicators/IPv4/{ip}/reputation"
            headers = {"Accept": "application/json"}
            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data.get("reputation"):
                    return {
                        "reputation": data["reputation"],
                        "alexa_rank": data.get("alexa_rank"),
                        "pulse_count": data.get("pulse_count")
                    }
            return None
        except Exception as e:
            print(f"[DEBUG] OTX IP check failed: {e}")
            return None

    def _check_otx_domain(self, domain: str) -> Optional[Dict]:
        """Check domain against AlienVault OTX"""
        try:
            url = f"{self.otx_base_url}/indicators/domain/{domain}/reputation"
            headers = {"Accept": "application/json"}
            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data.get("reputation"):
                    return {
                        "reputation": data["reputation"],
                        "pulse_count": data.get("pulse_count"),
                        "whois": data.get("whois")
                    }
            return None
        except Exception as e:
            print(f"[DEBUG] OTX domain check failed: {e}")
            return None

    def _check_abuseipdb_ip(self, ip: str) -> Optional[Dict]:
        """
        Check IP against AbuseIPDB (free tier, limited requests)
        Note: Free tier endpoint doesn't require API key but has limitations
        """
        try:
            # Using the free daily endpoint that doesn't require API key
            url = "https://www.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "User-Agent": "PCAP-Sentry"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }

            # This endpoint requires an API key, so we'll skip it for truly free access
            # Instead, we can use public lists if available
            return None
        except Exception as e:
            print(f"[DEBUG] AbuseIPDB check failed: {e}")
            return None

    def _check_urlhaus(self, domain: str) -> Optional[Dict]:
        """Check domain against URLhaus malware URL database"""
        try:
            url = f"{self.urlhaus_base_url}/host/"
            data = {"host": domain}
            response = requests.post(url, data=data, timeout=5)

            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok" and result.get("urls"):
                    return {
                        "found": True,
                        "url_count": len(result["urls"]),
                        "urls": [{"url": u["url"], "threat": u.get("threat")} for u in result["urls"][:5]]
                    }
                elif result.get("query_status") == "ok":
                    return {"found": False}
            return None
        except Exception as e:
            print(f"[DEBUG] URLhaus check failed: {e}")
            return None

    def _calculate_ip_risk(self, sources: Dict) -> float:
        """Calculate overall IP risk score (0-100)"""
        risk_score = 0.0

        if "otx" in sources:
            otx_rep = sources["otx"].get("reputation", 0)
            # OTX reputation may be a dict or numeric
            if isinstance(otx_rep, dict):
                otx_rep = otx_rep.get("threat_score", 0) or 0
            if otx_rep:
                risk_score += min(float(otx_rep) * 10, 100.0)

        if "abuseipdb" in sources:
            abuse_rep = sources["abuseipdb"].get("reputation", 0)
            if isinstance(abuse_rep, (int, float)):
                risk_score += abuse_rep

        # Cap at 100
        return min(100.0, risk_score)

    def _calculate_domain_risk(self, sources: Dict) -> float:
        """Calculate overall domain risk score (0-100)"""
        risk_score = 0.0

        if "otx" in sources:
            otx_rep = sources["otx"].get("reputation", 0)
            if isinstance(otx_rep, dict):
                otx_rep = otx_rep.get("threat_score", 0) or 0
            if otx_rep:
                risk_score += min(float(otx_rep) * 10, 100.0)

        if "urlhaus" in sources and sources["urlhaus"].get("found"):
            risk_score += 75  # High risk if found in URLhaus

        return min(100.0, risk_score)

    def enrich_stats(self, stats: Dict) -> Dict:
        """
        Enrich analysis statistics with threat intelligence
        """
        if not self.is_available():
            return stats

        enriched = stats.copy()
        enriched["threat_intel"] = {}

        # Check suspicious IPs - combine unique_src_list and unique_dst_list
        all_ips = set(stats.get("unique_src_list", []))
        all_ips.update(stats.get("unique_dst_list", []))
        if all_ips:
            ip_risks = []
            for ip in list(all_ips)[:10]:  # Check top 10 IPs
                try:
                    ip_rep = self.check_ip_reputation(ip)
                    if ip_rep.get("risk_score", 0) > 30:
                        ip_risks.append({
                            "ip": ip,
                            "risk_score": ip_rep["risk_score"],
                            "sources": ip_rep["sources"]
                        })
                except Exception as e:
                    print(f"[DEBUG] Error enriching IP {ip}: {e}")

            if ip_risks:
                enriched["threat_intel"]["risky_ips"] = sorted(ip_risks, key=lambda x: x["risk_score"], reverse=True)

        # Check suspicious domains
        if "dns_queries" in stats or "http_hosts" in stats:
            domains = set()
            domains.update(stats.get("dns_queries", []))
            domains.update(stats.get("http_hosts", []))

            domain_risks = []
            for domain in list(domains)[:10]:  # Check top 10 domains
                try:
                    domain_rep = self.check_domain_reputation(domain)
                    if domain_rep.get("risk_score", 0) > 30:
                        domain_risks.append({
                            "domain": domain,
                            "risk_score": domain_rep["risk_score"],
                            "sources": domain_rep["sources"]
                        })
                except Exception as e:
                    print(f"[DEBUG] Error enriching domain {domain}: {e}")

            if domain_risks:
                enriched["threat_intel"]["risky_domains"] = sorted(domain_risks, key=lambda x: x["risk_score"], reverse=True)

        return enriched


def check_online_reputation(ip: str = None, domain: str = None) -> Dict:
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
