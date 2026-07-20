"""Console output sink using rich for colored formatting."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from netguard.outputs.base import Alert, OutputSink

SEVERITY_COLORS = {
    "low": "blue",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


class ConsoleOutput(OutputSink):
    """Prints alerts to stdout with colored severity indicators."""

    def __init__(self, min_severity: str = "low") -> None:
        super().__init__(min_severity=min_severity)
        self._console = Console()

    async def emit(self, alert: Alert) -> None:
        if not self.should_emit(alert):
            return

        color = SEVERITY_COLORS.get(alert.severity, "white")
        text = Text()
        text.append(f"[{alert.severity.upper()}]", style=color)
        text.append(f" {alert.attack_type}", style="bold")
        text.append(f" | {alert.src_ip}:{alert.src_port} -> {alert.dst_ip}:{alert.dst_port}")
        text.append(f" | confidence={alert.confidence:.2f}")
        text.append(f" | {alert.description}", style="dim")

        self._console.print(text)
