from __future__ import annotations

from .models import AccessPoint, DetectionConfig, SuspiciousEvent
from .oui_db import get_vendor_name, load_whitelist
from .platform_scanner import normalize_security, get_gateway_oui


class DetectionEngine:
    def __init__(self, config):
        self.config = config
        self.last_ap = None

    def evaluate(self, networks):
        nets = list(networks)
        network_events = self.ssid_security_mix(nets)
        current = next((ap for ap in nets if ap.is_connected), None)
        if not current:
            return network_events
        precheck_events = []
        if self.is_complete(current):
            precheck_events = self.precheck(current)
        if self.last_ap is None:
            if self.is_complete(current):
                self.last_ap = current
            return network_events + precheck_events
        if not self.is_complete(current):
            return network_events
        if not self.is_complete(self.last_ap):
            self.last_ap = current
            return network_events + precheck_events
        compare_events = self.compare(self.last_ap, current)
        self.last_ap = current
        if compare_events:
            extra_reasons = []
            for event in precheck_events:
                if event.reason not in compare_events[0].reason:
                    extra_reasons.append(event.reason)
            if extra_reasons:
                compare_events[0].reason += "\n" + "\n".join(extra_reasons)
            return compare_events + network_events
        return network_events + precheck_events

    def compare(self, prev, curr):
        static_changed = False
        changes = []
        prev_vendor = get_vendor_name(prev.bssid)
        curr_vendor = get_vendor_name(curr.bssid)
        if prev.ssid != curr.ssid:
            static_changed = True
            changes.append(f"SSID: {prev.ssid or '—'} → {curr.ssid or '—'}")
        if prev.bssid != curr.bssid:
            static_changed = True
            changes.append(f"BSSID: {prev.bssid or '—'} → {curr.bssid or '—'}")
        if prev_vendor != curr_vendor:
            static_changed = True
            changes.append(f"Производитель: {curr_vendor} → {prev_vendor}")
        prev_sec = normalize_security(prev.security)
        curr_sec = normalize_security(curr.security)
        if prev_sec and curr_sec and prev_sec != curr_sec:
            static_changed = True
            changes.append(f"Шифрование: {prev.security or 'нет'} → {curr.security or 'нет'}")
        if prev.channel and curr.channel and prev.channel != curr.channel:
            static_changed = True
            changes.append(f"Канал: {prev.channel} → {curr.channel}")
        if prev.band and curr.band and prev.band != curr.band:
            static_changed = True
            changes.append(f"Диапазон: {prev.band} → {curr.band}")
        signal_changed = False
        if prev.signal is not None and curr.signal is not None:
            if abs(curr.signal - prev.signal) > self.config.signal_drop_db:
                signal_changed = True
                changes.append(f"Сигнал: {self.format_signal(prev.signal)} → {self.format_signal(curr.signal)}")
        if not static_changed and not signal_changed:
            return []
        severity = "critical" if static_changed else "medium"
        reason = "\n".join(changes)
        return [SuspiciousEvent(ap=curr, reason=reason, severity=severity)]

    def precheck(self, ap):
        events = []
        sec = normalize_security(ap.security)
        if sec in ("open", "wep"):
            events.append(SuspiciousEvent(ap=ap, reason=f"Незащищённая сеть ({sec})", severity="critical"))
        bssid = ap.bssid or ""
        if bssid:
            if self.is_laa(bssid):
                events.append(SuspiciousEvent(ap=ap, reason=f"Локально администрируемый BSSID {bssid}", severity="critical"))
            elif not self.is_known_oui(bssid):
                bssid_oui = self.oui(bssid)
                events.append(
                    SuspiciousEvent(
                        ap=ap,
                        reason=f"Производитель с OUI {bssid_oui} не найден в базе ({bssid})",
                        severity="medium",
                    )
                )
            gw_oui = get_gateway_oui()
            bssid_oui = self.oui(bssid)
            if gw_oui and bssid_oui and gw_oui != bssid_oui:
                if gw_oui not in load_whitelist() or bssid_oui not in load_whitelist():
                    gateway_vendor = get_vendor_name(gw_oui)
                    bssid_vendor = get_vendor_name(bssid_oui)
                    events.append(
                        SuspiciousEvent(
                            ap=ap,
                            reason=f"Производитель шлюза отличается от BSSID ({gateway_vendor}: {gw_oui} vs {bssid_vendor}: {bssid_oui})",
                            severity="medium",
                        )
                    )
        if ap.supports_wpa3 is True and sec and sec != "wpa3":
            events.append(SuspiciousEvent(ap=ap, reason=f"Возможный даунгрейд: адаптер поддерживает WPA3, сеть использует {sec}", severity="medium"))
        return events

    def format_signal(self, value):
        if value >= 0:
            pct = max(0, min(100, value))
            return f"{pct}%"
        pct = int((value + 100) * 100 / 70)
        pct = max(0, min(100, pct))
        return f"{pct}%"

    def is_complete(self, ap):
        return bool(ap and ap.ssid and ap.bssid and ap.security and ap.channel is not None and ap.signal is not None)

    def is_laa(self, bssid):
        try:
            first = int(bssid.split(":")[0], 16)
            return bool(first & 0x02)
        except Exception:
            return False

    def is_known_oui(self, bssid):
        prefix = bssid.lower().replace("-", ":").split(":")[:3]
        if len(prefix) < 3:
            return False
        oui = ":".join(prefix)
        return oui in load_whitelist()

    def oui(self, bssid):
        parts = bssid.lower().replace("-", ":").split(":")[:3]
        if len(parts) < 3:
            return ""
        return ":".join(parts)

    def ssid_security_mix(self, aps):
        by_ssid = {}
        for ap in aps:
            if not ap.ssid or not ap.security:
                continue
            sec = normalize_security(ap.security)
            by_ssid.setdefault(ap.ssid, set()).add(sec)
        events = []
        for ssid, secset in by_ssid.items():
            if len(secset) > 1:
                target = next((a for a in aps if a.ssid == ssid and a.is_connected), None) or next(a for a in aps if a.ssid == ssid)
                reason = f"Один SSID '{ssid}' с разными типами защиты: {', '.join(sorted(secset))}"
                events.append(SuspiciousEvent(ap=target, reason=reason, severity="medium"))
        return events
