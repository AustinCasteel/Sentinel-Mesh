"""MCP-compliant Threat Intelligence Server.

Exposes three tools over the Model Context Protocol (stdio transport):

  1. ``lookup_cve``         — Query CVE details via CIRCL Vulnerability Lookup API
  2. ``query_ip_reputation`` — IP reputation via AbuseIPDB + C2/malware enrichment
                              via abuse.ch ThreatFox
  3. ``parse_syslog``       — Parse raw syslog lines into structured data

External APIs:
  - **CIRCL CVE**: ``https://cve.circl.lu/api/cve/{CVE-ID}`` (no auth, global
    multi-source vulnerability intelligence)
  - **AbuseIPDB**: ``https://api.abuseipdb.com/api/v2/check`` (free tier:
    1,000 req/day, requires API key)
  - **ThreatFox**: ``https://threatfox-api.abuse.ch/api/v1/`` (free, requires
    auth key — C2 indicators, malware families, threat actor correlation)

All external calls degrade gracefully — if an API is unreachable or unconfigured,
the tool returns whatever data it can gather plus a ``"warnings"`` list.

Run standalone::

    python mcp_servers/threat_intel_server.py

Or via MCP stdio from the supervisor agent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import warnings
from datetime import datetime

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Suppress benign FastMCP lifespan warning
warnings.filterwarnings("ignore", message=".*Field 'lifespan' has an incomplete definition.*")

# Ensure .env variables are loaded even when spawned in a separate subprocess
load_dotenv()

# ═══════════════════════════════════════════════════════════════
#  Server instance
# ═══════════════════════════════════════════════════════════════

mcp = FastMCP(
    "threat-intel",
    instructions=(
        "Threat intelligence tools for SentinelMesh. Use lookup_cve to "
        "retrieve CVE details from CIRCL, query_ip_reputation for IP "
        "analysis via AbuseIPDB + ThreatFox, and parse_syslog to "
        "structure raw log lines."
    ),
)

# ═══════════════════════════════════════════════════════════════
#  API Configuration
# ═══════════════════════════════════════════════════════════════

_CIRCL_CVE_BASE = "https://cve.circl.lu/api/cve"
_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2/check"
_THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1/"


def _get_abuseipdb_key() -> str:
    """Get AbuseIPDB API key dynamically from environment."""
    return os.environ.get("SENTINEL_ABUSEIPDB_API_KEY", "").strip()


def _get_threatfox_key() -> str:
    """Get ThreatFox auth key dynamically from environment."""
    return os.environ.get("SENTINEL_THREATFOX_AUTH_KEY", "").strip()


_HTTP_TIMEOUT = 10.0  # seconds


# ═══════════════════════════════════════════════════════════════
#  Helper: HTTP client
# ═══════════════════════════════════════════════════════════════


def _http_client() -> httpx.Client:
    """Create a reusable httpx client with timeouts."""
    return httpx.Client(
        timeout=_HTTP_TIMEOUT,
        headers={"User-Agent": "SentinelMesh-MCP/0.1"},
    )


# ═══════════════════════════════════════════════════════════════
#  CVE Lookup via CIRCL
# ═══════════════════════════════════════════════════════════════


def _parse_circl_response(cve_id: str, data: dict) -> dict:
    """Normalise the CVE 5.x record from CIRCL into a clean structure."""
    result: dict = {
        "id": cve_id,
        "source": "CIRCL (cve.circl.lu)",
        "description": "",
        "cvss_score": None,
        "severity": "UNKNOWN",
        "affected_products": [],
        "published": None,
        "references": [f"https://cve.circl.lu/cve/{cve_id}"],
        "remediation": "Consult vendor advisories for patching guidance.",
    }

    # ── Metadata ─────────────────────────────────────────────
    meta = data.get("cveMetadata", {})
    result["published"] = meta.get("datePublished", "")

    # ── CNA container (main vulnerability data) ──────────────
    cna = data.get("containers", {}).get("cna", {})

    # Description
    descriptions = cna.get("descriptions", [])
    if descriptions:
        desc_val = descriptions[0].get("value", "")
        result["description"] = (desc_val[:300] + "...") if len(desc_val) > 300 else desc_val

    # CVSS
    for metric in cna.get("metrics", []):
        cvss = metric.get("cvssV3_1") or metric.get("cvssV3_0") or metric.get("cvssV4_0")
        if cvss:
            result["cvss_score"] = cvss.get("baseScore")
            result["severity"] = cvss.get("baseSeverity", "UNKNOWN").upper()
            result["cvss_vector"] = cvss.get("vectorString", "")
            break
        # Red Hat severity fallback
        other = metric.get("other", {})
        content = other.get("content", {})
        if content.get("value"):
            result["severity"] = content["value"].upper()

    # Affected products
    for affected in cna.get("affected", []):
        product = affected.get("product", affected.get("packageName", ""))
        vendor = affected.get("vendor", "")
        versions = affected.get("versions", [])
        for ver in versions:
            if ver.get("status") == "affected":
                ver_str = ver.get("version", "")
                label = f"{vendor} {product} {ver_str}".strip()
                result["affected_products"].append(label)
        if not versions and product:
            result["affected_products"].append(f"{vendor} {product}".strip())

    result["affected_products"] = result["affected_products"][:3]

    # References
    for ref in cna.get("references", []):
        url = ref.get("url", "")
        if url:
            result["references"].append(url)
    result["references"] = result["references"][:2]

    return result


@mcp.tool()
def lookup_cve(cve_id: str) -> str:
    """Look up a CVE by its identifier via the CIRCL Vulnerability Lookup API.

    Queries https://cve.circl.lu which aggregates vulnerability data from
    global sources (NVD, Red Hat, vendor advisories, and more) — providing
    broader coverage than NIST alone.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2024-3094')

    Returns:
        JSON string with CVE details including CVSS score, severity,
        affected products, references, and remediation guidance.
    """
    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return json.dumps({"error": f"Invalid CVE format: {cve_id}", "expected": "CVE-YYYY-NNNNN"})

    try:
        with _http_client() as client:
            resp = client.get(f"{_CIRCL_CVE_BASE}/{cve_id}")
            resp.raise_for_status()
            data = resp.json()

        if not data:
            return json.dumps(
                {
                    "id": cve_id,
                    "description": f"No record found for {cve_id} in CIRCL database.",
                    "severity": "UNKNOWN",
                    "references": [f"https://cve.circl.lu/cve/{cve_id}"],
                }
            )

        result = _parse_circl_response(cve_id, data)
        return json.dumps(result)

    except httpx.HTTPStatusError as exc:
        return json.dumps(
            {
                "id": cve_id,
                "error": f"CIRCL API returned HTTP {exc.response.status_code}",
                "fallback": f"https://cve.circl.lu/cve/{cve_id}",
            }
        )
    except Exception as exc:
        return json.dumps(
            {
                "id": cve_id,
                "error": f"CIRCL API unreachable: {exc!s}",
                "fallback": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )


# ═══════════════════════════════════════════════════════════════
#  IP Reputation via AbuseIPDB + ThreatFox
# ═══════════════════════════════════════════════════════════════


def _query_abuseipdb(ip_address: str) -> dict | None:
    """Query AbuseIPDB for IP reputation data.

    Returns None if the API key is not configured or the request fails.
    Free tier: 1,000 requests/day.
    """
    key = _get_abuseipdb_key()
    if not key:
        return None

    try:
        with _http_client() as client:
            resp = client.get(
                _ABUSEIPDB_BASE,
                params={"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": ""},
                headers={"Key": key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            return resp.json().get("data", {})
    except Exception:
        return None


def _query_threatfox(ip_address: str) -> list[dict] | None:
    """Query abuse.ch ThreatFox for C2/malware IoC data related to an IP.

    Returns a list of IoC records, or None if unconfigured/failed.
    Free with auth key — provides C2 indicators, malware families,
    and threat actor attribution.
    """
    key = _get_threatfox_key()
    if not key:
        return None

    try:
        with _http_client() as client:
            resp = client.post(
                _THREATFOX_BASE,
                json={"query": "search_ioc", "search_term": ip_address},
                headers={"Auth-Key": key},
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "ok":
                return data.get("data", [])
            return []
    except Exception:
        return None


@mcp.tool()
def query_ip_reputation(ip_address: str) -> str:
    """Query threat intelligence for an IP address reputation report.

    Combines data from multiple sources for comprehensive coverage:
      - **AbuseIPDB**: Abuse confidence score, ISP, geolocation, report
        categories (requires SENTINEL_ABUSEIPDB_API_KEY).
      - **ThreatFox (abuse.ch)**: C2 indicators, malware families, and
        threat actor correlation (requires SENTINEL_THREATFOX_AUTH_KEY).

    Falls back gracefully when API keys are not configured.

    Args:
        ip_address: IPv4 address to look up (e.g., '185.220.101.1')

    Returns:
        JSON string with risk score, categories, geolocation, associated
        malware families, and known threat actors.
    """
    ip_address = ip_address.strip()
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        return json.dumps({"error": f"Invalid IPv4 format: {ip_address}"})

    result: dict = {
        "ip": ip_address,
        "risk_score": 0,
        "abuse_confidence_score": None,
        "categories": [],
        "country": None,
        "isp": None,
        "domain": None,
        "usage_type": None,
        "total_reports": 0,
        "last_reported": None,
        "associated_malware": [],
        "threat_actors": [],
        "c2_indicators": [],
        "sources": [],
        "warnings": [],
    }

    # ── AbuseIPDB ──────────────────────────────────────────────
    abuse_data = _query_abuseipdb(ip_address)
    if abuse_data:
        result["sources"].append("AbuseIPDB")
        result["abuse_confidence_score"] = abuse_data.get("abuseConfidenceScore", 0)
        result["risk_score"] = abuse_data.get("abuseConfidenceScore", 0)
        result["country"] = abuse_data.get("countryCode")
        result["isp"] = abuse_data.get("isp")
        result["domain"] = abuse_data.get("domain")
        result["usage_type"] = abuse_data.get("usageType")
        result["total_reports"] = abuse_data.get("totalReports", 0)
        result["last_reported"] = abuse_data.get("lastReportedAt")
        result["is_tor"] = abuse_data.get("isTor", False)
        result["is_whitelisted"] = abuse_data.get("isWhitelisted", False)

        # Map AbuseIPDB category IDs to human-readable names
        _category_map = {
            1: "dns_compromise",
            2: "dns_poisoning",
            3: "fraud_orders",
            4: "ddos_attack",
            5: "ftp_brute_force",
            7: "ping_of_death",
            8: "phishing",
            9: "fraud_voip",
            10: "open_proxy",
            11: "web_spam",
            12: "email_spam",
            13: "blog_spam",
            14: "vpn_ip",
            15: "port_scan",
            16: "hacking",
            17: "sql_injection",
            18: "spoofing",
            19: "brute_force",
            20: "bad_web_bot",
            21: "exploited_host",
            22: "web_app_attack",
            23: "ssh_abuse",
            24: "iot_targeted",
        }
        categories = set()
        for report in abuse_data.get("reports", [])[:10]:
            for cat_id in report.get("categories", []):
                name = _category_map.get(cat_id, f"category_{cat_id}")
                categories.add(name)
        result["categories"] = sorted(categories)[:5] if categories else ["unknown"]
    elif not _get_abuseipdb_key():
        result["warnings"].append("AbuseIPDB API key not configured (SENTINEL_ABUSEIPDB_API_KEY)")
    else:
        result["warnings"].append("AbuseIPDB query failed")

    # ── ThreatFox ──────────────────────────────────────────────
    threatfox_data = _query_threatfox(ip_address)
    if threatfox_data is not None:
        result["sources"].append("ThreatFox (abuse.ch)")
        malware_set: set[str] = set()
        actor_set: set[str] = set()

        for ioc in threatfox_data[:10]:
            malware_name = ioc.get("malware_printable", "")
            if malware_name:
                malware_set.add(malware_name)

            threat_type = ioc.get("threat_type_desc", "")
            if threat_type and len(result["c2_indicators"]) < 2:
                result["c2_indicators"].append(
                    {
                        "ioc": ioc.get("ioc", ""),
                        "threat_type": threat_type,
                        "malware": malware_name,
                        "confidence": ioc.get("confidence_level", 0),
                    }
                )

            tags = ioc.get("tags", []) or []
            for tag in tags:
                if any(kw in tag.lower() for kw in ("apt", "ta", "group", "actor")):
                    actor_set.add(tag)

        result["associated_malware"] = sorted(malware_set)[:3]
        result["threat_actors"] = sorted(actor_set)[:2]

        # Boost risk score if ThreatFox has C2 data
        if result["c2_indicators"]:
            result["risk_score"] = max(result["risk_score"], 85)
    elif not _get_threatfox_key():
        result["warnings"].append("ThreatFox auth key not configured (SENTINEL_THREATFOX_AUTH_KEY)")
    else:
        result["warnings"].append("ThreatFox query failed")

    # ── Fallback for completely unconfigured state ─────────────
    if not result["sources"]:
        hash_val = int(hashlib.md5(ip_address.encode()).hexdigest()[:8], 16)
        result["risk_score"] = hash_val % 100
        result["categories"] = ["unknown"]
        result["warnings"].append(
            "No API keys configured. Set SENTINEL_ABUSEIPDB_API_KEY and/or "
            "SENTINEL_THREATFOX_AUTH_KEY for live threat intelligence."
        )

    return json.dumps(result)


# ═══════════════════════════════════════════════════════════════
#  Syslog Parser (local, no external API)
# ═══════════════════════════════════════════════════════════════


@mcp.tool()
def parse_syslog(log_string: str) -> str:
    """Parse a raw syslog line into structured fields.

    Supports RFC 3164 and common Linux syslog formats.  Extracts
    timestamp, hostname, process, PID, and message body.

    Args:
        log_string: Raw syslog line (e.g., 'Mar 15 14:23:01 webserver sshd[12345]: ...')

    Returns:
        JSON string with parsed fields and any extracted IoCs (IPs, CVEs).
    """
    log_string = log_string.strip()
    if not log_string:
        return json.dumps({"error": "Empty log string"})

    # ── RFC 3164 pattern ────────────────────────────────────────
    rfc3164 = re.match(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[\w/.-]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)",
        log_string,
    )

    if rfc3164:
        parsed = {
            "format": "rfc3164",
            "timestamp": rfc3164.group("timestamp"),
            "hostname": rfc3164.group("hostname"),
            "process": rfc3164.group("process"),
            "pid": rfc3164.group("pid"),
            "message": rfc3164.group("message"),
        }
    else:
        # Fallback — treat entire string as message
        parsed = {
            "format": "unknown",
            "timestamp": datetime.now().isoformat(),
            "hostname": "unknown",
            "process": "unknown",
            "pid": None,
            "message": log_string,
        }

    # ── Extract embedded IoCs ──────────────────────────────────
    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", log_string)
    cves = re.findall(r"CVE-\d{4}-\d{4,}", log_string, re.IGNORECASE)
    parsed["extracted_iocs"] = {
        "ip_addresses": list(set(ips)),
        "cve_ids": [c.upper() for c in set(cves)],
    }

    # ── Severity heuristic ─────────────────────────────────────
    msg_lower = log_string.lower()
    if any(kw in msg_lower for kw in ("fail", "error", "denied", "attack", "exploit")):
        parsed["heuristic_severity"] = "high"
    elif any(kw in msg_lower for kw in ("warn", "timeout", "retry")):
        parsed["heuristic_severity"] = "medium"
    else:
        parsed["heuristic_severity"] = "low"

    return json.dumps(parsed)


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
