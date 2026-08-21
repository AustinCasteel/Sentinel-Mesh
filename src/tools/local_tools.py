"""Deterministic local tools — pure Python utilities that don't require LLM calls.

These serve as fallback tools for offline / air-gapped operation and for
tasks that benefit from deterministic, auditable logic.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime

from langchain_core.tools import tool


@tool
def classify_severity(
    cvss_score: float,
    exploit_in_wild: bool = False,
    asset_criticality: str = "medium",
) -> str:
    """Deterministically classify alert severity from CVSS score and context.

    Args:
        cvss_score: CVSS v3 base score (0.0 - 10.0)
        exploit_in_wild: Whether an active exploit is known
        asset_criticality: Target asset criticality ('low', 'medium', 'high', 'critical')

    Returns:
        JSON with severity level, rationale, and recommended SLA.
    """
    criticality_boost = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(
        asset_criticality.lower(), 1
    )

    effective_score = min(
        10.0, cvss_score + (1.5 if exploit_in_wild else 0) + criticality_boost * 0.5
    )

    if effective_score >= 9.0:
        severity, sla = "critical", "15 minutes"
    elif effective_score >= 7.0:
        severity, sla = "high", "1 hour"
    elif effective_score >= 4.0:
        severity, sla = "medium", "4 hours"
    else:
        severity, sla = "low", "24 hours"

    return json.dumps(
        {
            "severity": severity,
            "effective_score": round(effective_score, 1),
            "cvss_base": cvss_score,
            "exploit_active": exploit_in_wild,
            "asset_criticality": asset_criticality,
            "response_sla": sla,
            "rationale": (
                f"Base CVSS {cvss_score} "
                f"{'+ active exploit bonus ' if exploit_in_wild else ''}"
                f"+ asset criticality ({asset_criticality}) "
                f"→ effective score {round(effective_score, 1)} → {severity}"
            ),
        }
    )


@tool
def extract_iocs(text: str) -> str:
    """Extract Indicators of Compromise (IoCs) from unstructured text.

    Scans for IPv4 addresses, domains, MD5/SHA-1/SHA-256 hashes, CVE IDs,
    email addresses, and URLs.

    Args:
        text: Raw text to scan for IoCs.

    Returns:
        JSON with categorised IoC lists and total count.
    """
    patterns = {
        "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "cve": r"CVE-\d{4}-\d{4,}",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "url": r"https?://[^\s<>\"']+",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    }

    results: dict[str, list[str]] = {}
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        # Deduplicate and validate
        unique = list(dict.fromkeys(matches))
        if ioc_type == "ipv4":
            unique = [ip for ip in unique if _is_valid_ip(ip)]
        results[ioc_type] = unique

    total = sum(len(v) for v in results.values())
    return json.dumps({"iocs": results, "total_count": total})


@tool
def validate_network_cidr(cidr: str) -> str:
    """Validate a network CIDR block and return its properties.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        JSON with network properties or validation error.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return json.dumps(
            {
                "valid": True,
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "netmask": str(network.netmask),
                "prefix_length": network.prefixlen,
                "num_hosts": network.num_addresses - 2
                if network.prefixlen < 31
                else network.num_addresses,
                "is_private": network.is_private,
                "is_global": network.is_global,
            }
        )
    except ValueError as exc:
        return json.dumps({"valid": False, "error": str(exc)})


@tool
def compute_file_hash(content: str, algorithm: str = "sha256") -> str:
    """Compute a cryptographic hash of the given content.

    Args:
        content: Text content to hash.
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256').

    Returns:
        JSON with the computed hash.
    """
    algo = algorithm.lower()
    if algo not in ("md5", "sha1", "sha256"):
        return json.dumps({"error": f"Unsupported algorithm: {algo}"})
    h = hashlib.new(algo, content.encode())
    return json.dumps(
        {
            "algorithm": algo,
            "hash": h.hexdigest(),
            "content_length": len(content),
            "computed_at": datetime.now().isoformat(),
        }
    )


@tool
def generate_firewall_rule(
    action: str,
    source_ip: str,
    destination_ip: str = "any",
    port: int | None = None,
    protocol: str = "tcp",
) -> str:
    """Generate a firewall rule in iptables and pf syntax.

    Args:
        action: 'block' or 'allow'
        source_ip: Source IP address or CIDR
        destination_ip: Destination IP address or CIDR (default: 'any')
        port: Destination port number (optional)
        protocol: Protocol ('tcp', 'udp', 'icmp')

    Returns:
        JSON with iptables and pf rule strings.
    """
    action = action.lower()
    if action not in ("block", "allow"):
        return json.dumps({"error": f"Invalid action: {action}. Use 'block' or 'allow'."})

    ipt_action = "DROP" if action == "block" else "ACCEPT"
    pf_action = "block" if action == "block" else "pass"

    # iptables rule
    ipt = f"iptables -A INPUT -s {source_ip}"
    if destination_ip != "any":
        ipt += f" -d {destination_ip}"
    ipt += f" -p {protocol}"
    if port:
        ipt += f" --dport {port}"
    ipt += f" -j {ipt_action}"

    # pf rule
    pf = f"{pf_action} in quick on egress proto {protocol} from {source_ip}"
    if destination_ip != "any":
        pf += f" to {destination_ip}"
    if port:
        pf += f" port {port}"

    return json.dumps(
        {
            "action": action,
            "source": source_ip,
            "destination": destination_ip,
            "port": port,
            "protocol": protocol,
            "rules": {"iptables": ipt, "pf": pf},
        }
    )


@tool
def query_knowledge_graph(entity: str) -> str:
    """Query the Neo4j Knowledge Graph for asset vulnerabilities, threat actors, and malware relationships.

    Args:
        entity: IP address, hostname, or CVE ID (e.g. 'web-server-01', '185.220.101.1', 'CVE-2024-3094').

    Returns:
        JSON representation of graph relationships and impacted nodes.
    """
    from src.memory.hybrid_retriever import KnowledgeGraph

    kg = KnowledgeGraph()
    try:
        if entity.upper().startswith("CVE-"):
            results = kg.query_by_cve(entity.upper())
        else:
            results = kg.query_by_ip_or_asset(entity)
        return json.dumps({"entity": entity, "graph_results": results})
    except Exception as exc:
        return json.dumps({"entity": entity, "error": str(exc)})
    finally:
        kg.close()


def _is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid, non-broadcast IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_multicast or addr.is_unspecified)
    except ValueError:
        return False


def get_local_tools() -> list:
    """Return all local deterministic tools as a list."""
    return [
        classify_severity,
        extract_iocs,
        validate_network_cidr,
        compute_file_hash,
        generate_firewall_rule,
        query_knowledge_graph,
    ]
