from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Config:
    """Configuration shared by the HTTP, device, Mercury, and KMS clients."""

    base_url: str = "https://webexapis.com/v1"
    timeout: float = 30.0
    default_headers: dict[str, str] = field(default_factory=dict)
    max_retries: int = 3
    retry_base_delay: float = 1.0

    wdm_url: str = "https://wdm-a.wbx2.com/wdm/api/v1/devices"
    device_ephemeral: bool = False
    device_ephemeral_ttl: int = 86400

    mercury_force_close_delay: float = 10.0
    mercury_ping_interval: float = 30.0
    mercury_pong_timeout: float = 10.0
    mercury_backoff_time_max: float = 32.0
    mercury_backoff_time_reset: float = 1.0
    mercury_max_retries: int = 3
    mercury_initial_connection_max_retries: int = 5
    mercury_fallback_websocket_url: str = "wss://mercury-connection-a.wbx2.com/mercury/device"

    kms_default_cluster: str = "a"
    kms_http_timeout: float = 10.0
    kms_response_timeout: float = 30.0
    disable_key_cache: bool = False
