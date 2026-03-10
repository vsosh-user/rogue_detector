from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

def utcnow():
    return datetime.utcnow()


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int | None
    signal: int | None
    security: str
    last_seen: datetime
    band: str | None = None
    rx_rate: float | None = None
    tx_rate: float | None = None
    data_rate: float | None = None
    is_connected: bool = False
    supports_wpa3: bool | None = None
    captive_redirect: bool | None = None

    def to_dict(self):
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "signal": self.signal,
            "security": self.security,
            "band": self.band,
            "rx_rate": self.rx_rate,
            "tx_rate": self.tx_rate,
            "data_rate": self.data_rate,
            "last_seen": self.last_seen.isoformat(),
            "is_connected": self.is_connected,
            "supports_wpa3": self.supports_wpa3,
            "captive_redirect": self.captive_redirect,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            ssid=data["ssid"],
            bssid=data["bssid"],
            channel=data.get("channel"),
            signal=data.get("signal"),
            security=data.get("security", ""),
            band=data.get("band"),
            rx_rate=data.get("rx_rate"),
            tx_rate=data.get("tx_rate"),
            data_rate=data.get("data_rate"),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            is_connected=data.get("is_connected", False),
            supports_wpa3=data.get("supports_wpa3"),
            captive_redirect=data.get("captive_redirect"),
        )


@dataclass
class NetworkHistory:
    ssid: str
    bssid: str
    security: str
    channel: int | None
    first_seen: datetime
    last_seen: datetime
    seen_count: int = 0
    signal_samples: list[int] = field(default_factory=list)

    def to_dict(self):
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "security": self.security,
            "channel": self.channel,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "seen_count": self.seen_count,
            "signal_samples": self.signal_samples,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            ssid=data["ssid"],
            bssid=data["bssid"],
            security=data["security"],
            channel=data.get("channel"),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            seen_count=data.get("seen_count", 0),
            signal_samples=data.get("signal_samples", []),
        )


@dataclass
class SuspiciousEvent:
    ap: AccessPoint
    reason: str
    severity: str
    timestamp: datetime = field(default_factory=utcnow)


@dataclass
class DetectionConfig:
    scan_interval_sec: int = 6
    signal_drop_db: int = 15
    channel_switch_threshold: int = 6
    new_bssid_window_sec: int = 600
    history_path: str | None = None
    min_history_points: int = 3
