"""SentinelMesh Interactive Terminal UI (TUI) Dashboard.

Provides a live terminal-based SOC command centre for monitoring,
inspecting, and simulating security alerts with real-time triage,
IoC extraction, and mitigation analysis.

Run:
    uv run python src/tui.py
    # or
    sentinel-tui
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, ClassVar

import httpx
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Markdown,
    RadioButton,
    RadioSet,
    Static,
    TabbedContent,
    TabPane,
)

logger = logging.getLogger(__name__)

# Sample alerts for live demonstration / portfolio presentation
PRESET_ALERTS = [
    {
        "name": "SSH Brute Force (Tor Exit Node)",
        "source": "syslog",
        "alert": "Mar 15 14:23:01 webserver sshd[12345]: Failed password for root from 185.220.101.1 port 22 ssh2",
        "expected_sev": "HIGH",
    },
    {
        "name": "CVE-2024-3094 Exploitation Attempt (XZ Backdoor)",
        "source": "syslog",
        "alert": "Mar 16 09:15:33 app-server-02 webapp[5678]: ERROR Attempted exploitation of CVE-2024-3094 detected from 45.33.32.156",
        "expected_sev": "CRITICAL",
    },
    {
        "name": "FortiOS SSL VPN Exploit (CVE-2024-21762)",
        "source": "siem",
        "alert": "Intrusion detected: FortiGate fw-edge-01 reports SSL VPN exploit attempt matching CVE-2024-21762 from external IP 185.220.101.1. Multiple failed authentication attempts observed.",
        "expected_sev": "CRITICAL",
    },
    {
        "name": "Log4Shell Remote Code Execution Variant",
        "source": "waf",
        "alert": "WAF Alert: JNDI lookup injection detected in User-Agent header matching CVE-2023-44228 pattern from source IP 198.51.100.23 targeting internal accounting app.",
        "expected_sev": "CRITICAL",
    },
    {
        "name": "Benign Routine DNS Query",
        "source": "syslog",
        "alert": "Mar 17 03:00:00 dns-resolver named[1234]: query: google.com IN A + (8.8.8.8)",
        "expected_sev": "INFO",
    },
    {
        "name": "Data Exfiltration via DNS Tunneling",
        "source": "dns",
        "alert": "DNS anomaly: High entropy subdomain queries detected for data-exfil.attacker.com from internal host 10.0.1.55 sending 450 requests in 60 seconds.",
        "expected_sev": "HIGH",
    },
]

SEVERITY_STYLES = {
    "CRITICAL": "[bold white on red] CRITICAL [/]",
    "HIGH": "[bold white on dark_orange] HIGH [/]",
    "MEDIUM": "[bold black on yellow] MEDIUM [/]",
    "LOW": "[bold white on dark_green] LOW [/]",
    "INFO": "[bold white on blue] INFO [/]",
    "UNKNOWN": "[dim white] UNKNOWN [/]",
}

STATUS_STYLES = {
    "COMPLETED": "[bold green]● COMPLETED[/]",
    "IN_PROGRESS": "[bold yellow]⟳ TRIAGING[/]",
    "FAILED": "[bold red]✗ FAILED[/]",
}


class SimulateAlertModal(ModalScreen[dict[str, Any] | None]):
    """Modal dialog to inject synthetic alerts for live demo."""

    DEFAULT_CSS = """
    SimulateAlertModal {
        align: center middle;
    }
    #modal-container {
        width: 75;
        height: auto;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #modal-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #radio-set {
        margin-bottom: 1;
    }
    #btn-container {
        align: right middle;
        height: auto;
    }
    Button {
        margin-left: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-container"):
            yield Label("⚡ Inject Synthetic Alert for Live Triage", id="modal-title")
            with RadioSet(id="radio-set"):
                for i, sample in enumerate(PRESET_ALERTS):
                    yield RadioButton(
                        f"{sample['name']} ({sample['expected_sev']})", value=(i == 0)
                    )
            with Horizontal(id="btn-container"):
                yield Button("Cancel", variant="default", id="btn-cancel")
                yield Button("Submit Alert", variant="primary", id="btn-submit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-submit":
            radio_set = self.query_one(RadioSet)
            idx = radio_set.pressed_index
            if 0 <= idx < len(PRESET_ALERTS):
                self.dismiss(PRESET_ALERTS[idx])
            else:
                self.dismiss(PRESET_ALERTS[0])


class SentinelMeshTUI(App[None]):
    """Interactive SentinelMesh SOC Terminal UI."""

    CSS = """
    Screen {
        background: $surface-darken-1;
    }
    #main-container {
        height: 1fr;
    }
    #left-pane {
        width: 42%;
        border-right: heavy $accent;
        padding: 0 1;
    }
    #right-pane {
        width: 58%;
        padding: 0 1;
    }
    #pane-header-left {
        text-style: bold;
        color: $accent;
        margin: 1 0;
    }
    #pane-header-right {
        text-style: bold;
        color: $accent;
        margin: 1 0;
    }
    #alert-table {
        height: 1fr;
    }
    #raw-alert-box {
        background: $panel;
        padding: 1;
        margin-bottom: 1;
        border: solid $primary;
    }
    #iocs-box {
        background: $panel;
        padding: 1;
        margin-bottom: 1;
        border: solid $secondary;
    }
    #details-scroll {
        height: 1fr;
    }
    .badge-critical {
        color: red;
        text-style: bold;
    }
    .badge-high {
        color: yellow;
        text-style: bold;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("s", "simulate_alert", "Simulate Alert", priority=True),
        Binding("r", "refresh_alerts", "Refresh Feed", priority=True),
        Binding("q", "quit", "Quit", priority=True),
    ]

    def __init__(self, api_base: str = "http://localhost:8000") -> None:
        super().__init__()
        self.api_base = api_base.rstrip("/")
        self.alerts_data: list[dict[str, Any]] = []
        self.selected_alert: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-container"):
            # Left pane: Alert Feed table
            with Vertical(id="left-pane"):
                yield Label("🛡 Active Ingested Alerts Feed", id="pane-header-left")
                yield DataTable(id="alert-table", cursor_type="row")

            # Right pane: Detail & Markdown views
            with Vertical(id="right-pane"):
                yield Label("📋 Incident Investigation & Mitigation", id="pane-header-right")
                with TabbedContent():
                    with (
                        TabPane("Executive Summary", id="tab-summary"),
                        VerticalScroll(id="details-scroll"),
                    ):
                        yield Markdown(
                            "### No Alert Selected\nSelect an alert from the left feed or press **[s]** to inject a synthetic alert.",
                            id="md-summary",
                        )
                    with TabPane("Telemetry & IoCs", id="tab-telemetry"), VerticalScroll():
                        yield Static("Raw Ingested Alert:", classes="header-label")
                        yield Static("No data", id="raw-alert-box")
                        yield Static(
                            "Extracted Indicators of Compromise (IoCs):", classes="header-label"
                        )
                        yield Static("No IoCs", id="iocs-box")
                    with TabPane("Mitigation Plan", id="tab-mitigation"), VerticalScroll():
                        yield Markdown("No mitigation plan available.", id="md-mitigation")

        yield Footer()

    async def on_mount(self) -> None:
        """Initialize table and start periodic poll."""
        table = self.query_one(DataTable)
        table.add_columns("Severity", "Source", "Alert Snippet", "Status")
        self.action_refresh_alerts()
        self.set_interval(3.0, self.action_refresh_alerts)

    @work(exclusive=True)
    async def action_refresh_alerts(self) -> None:
        """Fetch latest alerts from the SentinelMesh backend API."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.api_base}/v1/alerts?limit=25")
                if resp.status_code == 200:
                    self.alerts_data = resp.json()
                    self._update_table()
        except Exception:
            # Fallback to local session store if API is offline
            try:
                from src.memory.session_store import alert_store

                self.alerts_data = alert_store.list_alerts(limit=25)
                self._update_table()
            except Exception:
                pass

    def _update_table(self) -> None:
        """Render alert rows into the DataTable."""
        table = self.query_one(DataTable)
        curr_row = table.cursor_row
        table.clear()

        for alert in self.alerts_data:
            sev = alert.get("severity", "UNKNOWN").upper()
            sev_badge = SEVERITY_STYLES.get(sev, f"[{sev}]")
            status = alert.get("status", "IN_PROGRESS")
            status_badge = STATUS_STYLES.get(status, f"[{status}]")
            source = alert.get("source", "log")
            raw = alert.get("raw_alert", "")
            preview = (raw[:38] + "...") if len(raw) > 38 else raw

            table.add_row(
                sev_badge,
                source.upper(),
                preview,
                status_badge,
                key=alert.get("alert_id") or alert.get("session_id"),
            )

        if self.alerts_data:
            if curr_row is not None and curr_row < len(self.alerts_data):
                table.move_cursor(row=curr_row)
                self._display_alert(self.alerts_data[curr_row])
            elif not self.selected_alert:
                table.move_cursor(row=0)
                self._display_alert(self.alerts_data[0])

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in the alerts table."""
        idx = event.cursor_row
        if 0 <= idx < len(self.alerts_data):
            self._display_alert(self.alerts_data[idx])

    def _display_alert(self, alert: dict[str, Any]) -> None:
        """Populate the right-side inspector with the selected alert details."""
        self.selected_alert = alert

        # 1. Executive Summary Markdown
        md_summary = self.query_one("#md-summary", Markdown)
        resp = alert.get("final_response", "")
        if resp:
            md_summary.update(resp)
        elif alert.get("status") == "IN_PROGRESS":
            md_summary.update(
                f"### ⟳ Triage in Progress...\n\n"
                f"**Alert ID**: `{alert.get('alert_id')}`  \n"
                f"**Ingested At**: {alert.get('created_at')}  \n\n"
                f"The supervisor agent is actively coordinating between Tier-1 Triage, MCP Threat Intelligence, and the Mitigation Engineer."
            )
        elif alert.get("error"):
            md_summary.update(f"### ✗ Pipeline Error\n```\n{alert.get('error')}\n```")
        else:
            md_summary.update("No response data available.")

        # 2. Raw Telemetry & IoCs
        raw_box = self.query_one("#raw-alert-box", Static)
        raw_box.update(
            f"ID: {alert.get('alert_id')} | Source: {alert.get('source')}\n"
            f"Timestamp: {alert.get('created_at')}\n"
            f"Duration: {alert.get('duration_seconds', 0)}s\n\n"
            f"{alert.get('raw_alert')}"
        )

        iocs_box = self.query_one("#iocs-box", Static)
        iocs = alert.get("iocs", [])
        if iocs:
            iocs_box.update("\n".join(f"• [bold cyan]{ioc}[/]" for ioc in iocs))
        else:
            iocs_box.update("[dim]No indicators extracted yet[/]")

        # 3. Mitigation Plan Tab
        md_mitigation = self.query_one("#md-mitigation", Markdown)
        if "### Mitigation" in resp or "Mitigation Actions" in resp:
            # Extract mitigation portion if available
            parts = resp.split("### Mitigation")
            if len(parts) > 1:
                md_mitigation.update("### Mitigation" + parts[1])
            else:
                md_mitigation.update(resp)
        else:
            md_mitigation.update("Mitigation details are embedded in the Executive Summary tab.")

    def action_simulate_alert(self) -> None:
        """Open modal to select and inject a sample alert."""

        def _on_modal_dismiss(result: dict[str, Any] | None) -> None:
            if result:
                self.trigger_triage(result["alert"], result["source"])

        self.push_screen(SimulateAlertModal(), _on_modal_dismiss)

    @work(exclusive=False)
    async def trigger_triage(self, alert_text: str, source: str) -> None:
        """Send an alert to the backend API."""
        try:
            # Optimistically add to local UI table
            local_id = f"ALT-{datetime.now().strftime('%H%M%S')}"
            new_record = {
                "alert_id": local_id,
                "session_id": local_id,
                "source": source,
                "raw_alert": alert_text,
                "severity": "UNKNOWN",
                "status": "IN_PROGRESS",
                "final_response": "",
                "iocs": [],
                "created_at": datetime.now().isoformat(),
            }
            self.alerts_data.insert(0, new_record)
            self._update_table()

            async with httpx.AsyncClient(timeout=180.0) as client:
                resp = await client.post(
                    f"{self.api_base}/v1/triage",
                    json={"alert": alert_text, "source": source},
                )
                if resp.status_code == 200:
                    self.action_refresh_alerts()
                else:
                    new_record["status"] = "FAILED"
                    new_record["error"] = f"HTTP {resp.status_code}: {resp.text}"
                    self._update_table()
        except Exception:
            # Standalone direct run fallback if API is not running
            try:
                from src.agents.supervisor import run_pipeline
                from src.core.llm_factory import get_llm

                llm = get_llm()
                res = await run_pipeline(alert=alert_text, llm=llm, source=source)
                new_record["status"] = "COMPLETED"
                new_record["final_response"] = res.get("final_response", "")
                self._update_table()
            except Exception as inner_exc:
                new_record["status"] = "FAILED"
                new_record["error"] = str(inner_exc)
                self._update_table()


def main() -> None:
    """Entry point for the SentinelMesh TUI."""
    app = SentinelMeshTUI()
    app.run()


if __name__ == "__main__":
    main()
