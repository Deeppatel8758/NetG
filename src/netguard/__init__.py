"""NetGuard — Real-time network anomaly detection."""

__version__ = "0.1.0"

from netguard.core.engine import NetGuard
from netguard.adapters.base import NetworkFlow
from netguard.outputs.base import Alert

__all__ = ["NetGuard", "NetworkFlow", "Alert", "__version__"]
