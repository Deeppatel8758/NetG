"""Alert output sinks."""

from netguard.outputs.base import Alert, OutputSink
from netguard.outputs.console import ConsoleOutput

__all__ = ["OutputSink", "ConsoleOutput", "Alert"]


def __getattr__(name: str):
    if name == "WebhookOutput":
        from netguard.outputs.webhook import WebhookOutput
        return WebhookOutput
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
