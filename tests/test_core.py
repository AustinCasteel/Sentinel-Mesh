"""Unit tests for SentinelMesh core components."""

import json

from mcp_servers.threat_intel_server import parse_syslog
from src.agents.state import (
    MitigationAction,
    MitigationPlan,
    Severity,
    ThreatIndicator,
    TriageResult,
)
from src.config import LLMProvider, Settings
from src.tools.local_tools import (
    classify_severity,
    compute_file_hash,
    extract_iocs,
    generate_firewall_rule,
    validate_network_cidr,
)


def test_settings_default():
    settings = Settings()
    assert settings.llm_provider in [
        LLMProvider.OPENAI,
        LLMProvider.OLLAMA,
        LLMProvider.LEMONADE,
        LLMProvider.BEDROCK,
    ]
    assert settings.max_retries >= 1


def test_state_models():
    indicator = ThreatIndicator(
        indicator_type="ip",
        value="185.220.101.1",
        confidence=0.95,
        context="SSH failed login",
    )
    triage = TriageResult(
        severity=Severity.HIGH,
        summary="Brute force attack detected",
        indicators=[indicator],
        affected_assets=["webserver-01"],
        attack_vector="T1110 - Brute Force",
        requires_escalation=False,
    )
    assert triage.severity == Severity.HIGH
    assert len(triage.indicators) == 1

    action = MitigationAction(
        action_id="MIT-001",
        title="Block malicious IP",
        description="Drop inbound traffic from 185.220.101.1",
        priority=1,
        automated=True,
        commands=["iptables -A INPUT -s 185.220.101.1 -j DROP"],
    )
    plan = MitigationPlan(
        incident_id="INC-001",
        actions=[action],
        estimated_impact="Blocks attacker traffic without impacting internal services",
        rollback_steps=["iptables -D INPUT -s 185.220.101.1 -j DROP"],
    )
    assert plan.incident_id == "INC-001"
    assert len(plan.actions) == 1


def test_extract_iocs():
    text = "Attack from 192.168.1.50 and 203.0.113.195 exploiting CVE-2024-3094 with hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = json.loads(extract_iocs.invoke({"text": text}))
    iocs = result["iocs"]

    assert "192.168.1.50" in iocs["ipv4"]
    assert "203.0.113.195" in iocs["ipv4"]
    assert "CVE-2024-3094" in iocs["cve"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["sha256"]
    assert result["total_count"] >= 4


def test_validate_network_cidr():
    valid = json.loads(validate_network_cidr.invoke({"cidr": "192.168.1.0/24"}))
    assert valid["valid"] is True
    assert valid["is_private"] is True
    assert valid["prefix_length"] == 24

    invalid = json.loads(validate_network_cidr.invoke({"cidr": "invalid-cidr"}))
    assert invalid["valid"] is False


def test_generate_firewall_rule():
    rule_drop = json.loads(
        generate_firewall_rule.invoke(
            {
                "action": "block",
                "source_ip": "185.220.101.1",
                "port": 22,
                "protocol": "tcp",
            }
        )
    )
    assert "iptables -A INPUT -s 185.220.101.1" in rule_drop["rules"]["iptables"]
    assert "--dport 22" in rule_drop["rules"]["iptables"]
    assert "-j DROP" in rule_drop["rules"]["iptables"]
    assert "block in quick" in rule_drop["rules"]["pf"]


def test_classify_severity():
    critical = json.loads(
        classify_severity.invoke(
            {
                "cvss_score": 9.8,
                "exploit_in_wild": True,
                "asset_criticality": "critical",
            }
        )
    )
    assert critical["severity"] == "critical"
    assert critical["response_sla"] == "15 minutes"

    low = json.loads(
        classify_severity.invoke(
            {
                "cvss_score": 2.0,
                "exploit_in_wild": False,
                "asset_criticality": "low",
            }
        )
    )
    assert low["severity"] == "low"


def test_compute_file_hash():
    res = json.loads(compute_file_hash.invoke({"content": "hello world", "algorithm": "sha256"}))
    assert res["hash"] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_syslog_parser():
    raw_log = "Mar 15 14:23:01 webserver sshd[12345]: Failed password for root from 185.220.101.1 port 22 ssh2"
    result = json.loads(parse_syslog(raw_log))

    assert result["hostname"] == "webserver"
    assert result["process"] == "sshd"
    assert "185.220.101.1" in result["extracted_iocs"]["ip_addresses"]
    assert result["heuristic_severity"] == "high"


def test_query_knowledge_graph():
    from src.tools.local_tools import query_knowledge_graph

    res = json.loads(query_knowledge_graph.invoke({"entity": "web-server-01"}))
    assert res["entity"] == "web-server-01"
    assert "graph_results" in res


def test_alert_store():
    from src.memory.session_store import AlertStore

    store = AlertStore(max_history=5)
    rec = store.record_alert("ALT-001", "sess-1", "syslog", "Test alert content")
    assert rec.alert_id == "ALT-001"
    assert rec.status == "IN_PROGRESS"

    updated = store.update_alert(
        "sess-1",
        severity="CRITICAL",
        status="COMPLETED",
        final_response="Executive Summary: Critical incident mitigated.",
        iocs=["1.2.3.4"],
    )
    assert updated is not None
    assert updated.severity == "CRITICAL"
    assert updated.status == "COMPLETED"
    assert "1.2.3.4" in updated.iocs

    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "ALT-001"
