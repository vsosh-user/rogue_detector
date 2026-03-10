from __future__ import annotations

import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path

from .models import AccessPoint


MAC_RE = re.compile(r"[0-9a-f]{2}([:-][0-9a-f]{2}){5}")
LOCAL_IP_RE = re.compile(r"^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.")


class WifiScanner:
    def scan(self):
        raise NotImplementedError


def normalize_security(value):
    text = (value or "").lower()
    if "wpa3" in text:
        return "wpa3"
    if "wpa2" in text:
        return "wpa2"
    if "wpa" in text:
        return "wpa"
    if "wep" in text:
        return "wep"
    if "open" in text or "none" in text:
        return "open"
    return text


def channel_to_band(channel):
    if channel is None:
        return None
    if channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if channel >= 180:
        return "6 GHz"
    return None


def freq_to_band(freq):
    if freq is None:
        return None
    if 2400 <= freq <= 2500:
        return "2.4 GHz"
    if 4900 <= freq <= 5900:
        return "5 GHz"
    if 5925 <= freq <= 7125:
        return "6 GHz"
    return None


def decode_command_output(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    for encoding in ("utf-8", "cp866", "cp1251"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def run_command(args, timeout=None):
    proc = subprocess.run(
        args,
        capture_output=True,
        text=False,
        check=False,
        timeout=timeout,
    )
    proc.stdout = decode_command_output(proc.stdout)
    proc.stderr = decode_command_output(proc.stderr)
    return proc


def stdout_lines(proc):
    return (proc.stdout or "").splitlines()


class MacScanner(WifiScanner):
    AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    def __init__(self):
        self.supports_wpa3 = None
        self.captive_cache = None

    def scan(self):
        results = []
        now = datetime.utcnow()
        airport = Path(self.AIRPORT_PATH)
        if not airport.exists():
            return results
        try:
            connected = self.connected_info()
            self.captive_cache = probe_captive_redirect()
            proc = run_command(["sudo", str(airport), "-s"])
            lines = stdout_lines(proc)
            for line in lines[1:]:
                if not line.strip():
                    continue
                mac_match = MAC_RE.search(line.lower())
                if not mac_match:
                    continue
                parts = re.split(r"\s{2,}", line.strip())
                if len(parts) < 5:
                    continue
                ssid, bssid, rssi, channel, security = (
                    parts[0],
                    mac_match.group(0),
                    parts[2],
                    parts[3].split()[0],
                    parts[-1],
                )
                results.append(
                    AccessPoint(
                        ssid=ssid,
                        bssid=bssid.lower().replace("-", ":"),
                        channel=int(channel) if channel.isdigit() else None,
                        signal=int(rssi) if rssi.lstrip("-").isdigit() else None,
                        security=normalize_security(security),
                        band=channel_to_band(int(channel)) if channel.isdigit() else None,
                        rx_rate=None,
                        tx_rate=None,
                        data_rate=None,
                        last_seen=now,
                        is_connected=connected and connected.get("bssid") == bssid.lower(),
                        supports_wpa3=self.supports_wpa3,
                        captive_redirect=self.captive_cache,
                    )
                )
            if connected and all(ap.bssid != connected.get("bssid") for ap in results):
                results.append(
                    AccessPoint(
                        ssid=connected.get("ssid") or "<current>",
                        bssid=connected.get("bssid") or "",
                        channel=connected.get("channel"),
                        signal=connected.get("signal"),
                        security=connected.get("security", "unknown"),
                        band=channel_to_band(connected.get("channel")),
                        rx_rate=connected.get("rx_rate"),
                        tx_rate=connected.get("tx_rate"),
                        data_rate=None,
                        last_seen=now,
                        is_connected=True,
                        supports_wpa3=self.supports_wpa3,
                        captive_redirect=self.captive_cache,
                    )
                )
        except Exception:
            return results
        return results

    def connected_info(self):
        airport = Path(self.AIRPORT_PATH)
        info = {}
        try:
            proc = run_command([str(airport), "-I"])
            for line in stdout_lines(proc):
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                info[key.strip().lower()] = value.strip()
        except Exception:
            info = {}
        if not info:
            return self.connected_from_profiler()
        security = info.get("link auth") or info.get("auth") or info.get("802.11 auth") or ""
        channel = None
        if info.get("channel"):
            raw_ch = info["channel"].split(",", 1)[0].strip()
            if raw_ch.isdigit():
                channel = int(raw_ch)
        signal = None
        if info.get("agrctlrssi") and info["agrctlrssi"].lstrip("-").isdigit():
            signal = int(info["agrctlrssi"])
        bssid = (info.get("bssid") or "").lower().replace("-", ":")
        if not MAC_RE.match(bssid):
            ic_bssid = self.bssid_from_ipconfig()
            if ic_bssid:
                bssid = ic_bssid
        if not MAC_RE.match(bssid):
            bssid = self.router_mac() or ""
        rx_rate = None
        tx_rate = None
        if info.get("lastrxrate") and info["lastrxrate"].replace(".", "", 1).isdigit():
            rx_rate = float(info["lastrxrate"])
        if info.get("lasttxrate") and info["lasttxrate"].replace(".", "", 1).isdigit():
            tx_rate = float(info["lasttxrate"])
        return {
            "ssid": info.get("ssid"),
            "bssid": bssid or "",
            "security": normalize_security(security),
            "channel": channel,
            "signal": signal,
            "band": channel_to_band(channel),
            "rx_rate": rx_rate,
            "tx_rate": tx_rate,
        }

    def bssid_from_ipconfig(self):
        try:
            proc = run_command(["ipconfig", "getsummary", "en0"])
        except Exception:
            return None
        for line in stdout_lines(proc):
            match = MAC_RE.search(line.lower())
            if match:
                return match.group(0).replace("-", ":")
        return None

    def fallback_bssid(self):
        try:
            proc = run_command(["system_profiler", "SPAirPortDataType"], timeout=10)
        except Exception:
            return None
        current_section = False
        for line in stdout_lines(proc):
            if "Current Network Information" in line:
                current_section = True
                continue
            if current_section and "BSSID:" in line:
                candidate = line.split("BSSID:", 1)[1].strip().lower()
                if MAC_RE.match(candidate):
                    return candidate
            if current_section and line.strip() == "":
                break
        return None

    def connected_from_profiler(self):
        try:
            proc = run_command(["system_profiler", "SPAirPortDataType"], timeout=10)
        except Exception:
            return None
        current_section = False
        ssid = bssid = None
        channel = None
        signal = None
        for line in stdout_lines(proc):
            if "Current Network Information" in line:
                current_section = True
                continue
            if current_section:
                if "SSID:" in line:
                    ssid = line.split("SSID:", 1)[1].strip()
                elif "BSSID:" in line:
                    candidate = line.split("BSSID:", 1)[1].strip().lower().replace("-", ":")
                    if MAC_RE.match(candidate):
                        bssid = candidate
                elif "Channel:" in line:
                    ch_val = line.split("Channel:", 1)[1].strip()
                    if ch_val.split()[0].isdigit():
                        channel = int(ch_val.split()[0])
                elif "Signal" in line and line.split(":")[-1].strip().lstrip("-").isdigit():
                    signal = int(line.split(":")[-1].strip())
                if line.strip() == "":
                    break
        if not ssid and not bssid:
            return None
        return {
            "ssid": ssid,
            "bssid": bssid or "",
            "channel": channel,
            "signal": signal,
            "security": "",
            "band": channel_to_band(channel),
            "rx_rate": None,
            "tx_rate": None,
        }

    def router_mac(self):
        router_ip = None
        try:
            proc = run_command(["route", "-n", "get", "default"])
            for line in stdout_lines(proc):
                if "gateway:" in line:
                    router_ip = line.split("gateway:", 1)[1].strip()
                    break
        except Exception:
            router_ip = None
        if not router_ip:
            return None
        try:
            proc = run_command(["arp", "-n", router_ip])
        except Exception:
            return None
        for line in stdout_lines(proc):
            match = MAC_RE.search(line.lower())
            if match:
                return match.group(0).replace("-", ":")
        return None

    def scan_for_bssid(self, ssid):
        airport = Path(self.AIRPORT_PATH)
        try:
            proc = run_command([str(airport), "-s"], timeout=8)
        except Exception:
            return None
        for line in stdout_lines(proc)[1:]:
            if not line.strip():
                continue
            mac_match = MAC_RE.search(line.lower())
            if not mac_match:
                continue
            bssid_val = mac_match.group(0).replace("-", ":")
            ssid_val = line.strip().split()[0]
            if ssid_val == ssid:
                return bssid_val
        return None


class LinuxScanner(WifiScanner):
    def __init__(self):
        self.supports_wpa3 = self.detect_wpa3_support()
        self.captive_cache = None

    def scan(self):
        now = datetime.utcnow()
        results = []
        cmd = ["nmcli", "-t", "-e", "yes", "-f", "ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY", "dev", "wifi"]
        try:
            proc = run_command(cmd)
            self.captive_cache = probe_captive_redirect()
        except FileNotFoundError:
            connected = self.current_iw_link()
            if connected:
                results.append(connected)
            return results
        iface = self.wifi_iface()
        for line in stdout_lines(proc):
            if not line:
                continue
            parts = self.parse_nmcli_terse_line(line)
            if len(parts) < 7:
                continue
            active, ssid, bssid, channel, rate, signal, security = parts[:7]
            results.append(
                AccessPoint(
                    ssid=ssid or "<hidden>",
                    bssid=bssid.lower(),
                    channel=int(channel) if channel.isdigit() else None,
                    signal=int(signal) if signal.isdigit() else None,
                    security=normalize_security(security or "open"),
                    band=channel_to_band(int(channel)) if channel.isdigit() else None,
                    rx_rate=float(rate.replace("Mbit/s", "")) if rate else None,
                    tx_rate=None,
                    data_rate=float(rate.replace("Mbit/s", "")) if rate else None,
                    last_seen=now,
                    is_connected=active.lower() in ("yes", "да", "true", "*"),
                    supports_wpa3=self.supports_wpa3,
                    captive_redirect=self.captive_cache,
                )
            )
        current = self.current_connection(iface)
        if current and all(ap.bssid != current.get("bssid") for ap in results):
            results.append(
                AccessPoint(
                    ssid=current.get("ssid") or "<current>",
                    bssid=current.get("bssid") or "",
                    channel=current.get("channel"),
                    signal=current.get("signal"),
                    security=normalize_security(current.get("security") or "unknown"),
                    band=current.get("band"),
                    rx_rate=current.get("rate"),
                    tx_rate=current.get("tx_rate"),
                    data_rate=None,
                    last_seen=now,
                    is_connected=True,
                    supports_wpa3=self.supports_wpa3,
                    captive_redirect=self.captive_cache,
                )
            )
        fallback_current = self.current_iw_link()
        if fallback_current:
            matched = False
            for ap in results:
                same_bssid = fallback_current.bssid and ap.bssid == fallback_current.bssid
                same_ssid = fallback_current.ssid and ap.ssid == fallback_current.ssid
                if same_bssid or same_ssid:
                    ap.is_connected = True
                    ap.signal = fallback_current.signal or ap.signal
                    ap.band = fallback_current.band or ap.band
                    matched = True
                    break
            if not matched and not any(ap.is_connected for ap in results):
                fallback_current.supports_wpa3 = self.supports_wpa3
                fallback_current.captive_redirect = self.captive_cache
                results.append(fallback_current)
        return results

    def wifi_iface(self):
        try:
            proc = run_command(["nmcli", "-t", "-e", "yes", "-f", "DEVICE,TYPE,STATE", "dev"])
            for line in stdout_lines(proc):
                if not line:
                    continue
                parts = self.parse_nmcli_terse_line(line)
                if len(parts) < 3:
                    continue
                dev, typ, state = parts[0], parts[1], parts[2]
                if typ == "wifi" and state != "unavailable":
                    return dev
        except Exception:
            pass
        try:
            proc = run_command(["iw", "dev"])
            for line in stdout_lines(proc):
                if line.strip().startswith("Interface "):
                    return line.split()[1].strip()
        except Exception:
            pass
        return None

    def current_connection(self, iface):
        try:
            proc = run_command(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "GENERAL.CONNECTION,GENERAL.BSSID,GENERAL.SIGNAL,GENERAL.SECURITY,GENERAL.CHAN,GENERAL.RATE",
                    "device",
                    "show",
                    iface or "wlan0",
                ]
            )
        except FileNotFoundError:
            return None
        info = {}
        for line in stdout_lines(proc):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key.endswith("general.connection"):
                info["ssid"] = value
            elif key.endswith("general.bssid"):
                info["bssid"] = value.lower()
            elif key.endswith("general.signal") and value.isdigit():
                info["signal"] = int(value)
            elif key.endswith("general.security"):
                info["security"] = value
            elif key.endswith("general.chan") and value.isdigit():
                info["channel"] = int(value)
            elif key.endswith("general.rate"):
                try:
                    info["rate"] = float(value.replace("Mbit/s", ""))
                except Exception:
                    pass
        if info.get("ssid") and not info.get("bssid"):
            iw_current = self.current_iw_link()
            if iw_current:
                info["bssid"] = iw_current.bssid or info.get("bssid")
                info["signal"] = iw_current.signal if iw_current.signal is not None else info.get("signal")
                info["band"] = iw_current.band or info.get("band")
        return info or None

    def parse_nmcli_terse_line(self, line):
        parts = []
        current = []
        escaped = False
        for ch in line:
            if escaped:
                current.append(ch)
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == ":":
                parts.append("".join(current))
                current = []
                continue
            current.append(ch)
        parts.append("".join(current))
        return parts

    def detect_wpa3_support(self):
        try:
            proc = run_command(["iw", "list"], timeout=5)
        except Exception:
            return None
        text = (proc.stdout or "").lower()
        if not text:
            return None
        keywords = ("sae", "wpa3", "suite b 192", "owe")
        return any(k in text for k in keywords)

    def current_iw_link(self):
        try:
            proc = run_command(["iw", "dev", self.wifi_iface() or "wlan0", "link"])
        except FileNotFoundError:
            return None
        data = {}
        for line in stdout_lines(proc):
            if "Connected to" in line:
                data["bssid"] = line.split()[-1].lower()
            elif line.strip().startswith("SSID:"):
                data["ssid"] = line.split("SSID:", 1)[1].strip()
            elif line.strip().startswith("freq:"):
                freq = line.split("freq:", 1)[1].strip()
                if freq.isdigit():
                    data["frequency"] = int(freq)
            elif line.strip().startswith("signal:"):
                sig = line.split("signal:", 1)[1].strip().split()[0]
                if sig.lstrip("-").isdigit():
                    data["signal"] = int(sig)
        if not data:
            return None
        band = freq_to_band(data.get("frequency"))
        return AccessPoint(
            ssid=data.get("ssid") or "<current>",
            bssid=data.get("bssid") or "",
            channel=None,
            signal=data.get("signal"),
            security="unknown",
            band=band,
            rx_rate=None,
            tx_rate=None,
            data_rate=None,
            last_seen=datetime.utcnow(),
            is_connected=True,
        )


class WindowsScanner(WifiScanner):
    def scan(self):
        now = datetime.utcnow()
        results = []
        proc = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
        lines = stdout_lines(proc)
        current_ssid = None
        for line in lines:
            if self.is_ssid_line(line):
                parts = line.split(":", 1)
                current_ssid = parts[1].strip() if len(parts) > 1 else None
            elif self.is_bssid_line(line):
                bssid = self.extract_mac(line.split(":", 1)[1].strip().lower())
                results.append(
                    AccessPoint(
                        ssid=current_ssid or "<unknown>",
                        bssid=bssid,
                        channel=None,
                        signal=None,
                        security="unknown",
                        band=None,
                        rx_rate=None,
                        tx_rate=None,
                        data_rate=None,
                        last_seen=now,
                        is_connected=False,
                        captive_redirect=None,
                    )
                )
            elif self.is_signal_line(line) and results:
                value = line.split(":", 1)[1].strip().replace("%", "")
                if value.isdigit():
                    results[-1].signal = int(value)
            elif self.is_auth_line(line) and results:
                auth = line.split(":", 1)[1].strip()
                results[-1].security = normalize_security(auth)
            elif self.is_channel_line(line) and results:
                ch_val = line.split(":", 1)[1].strip()
                if ch_val.isdigit():
                    results[-1].channel = int(ch_val)
                    results[-1].band = channel_to_band(results[-1].channel)
        iface_info = self.current_interface()
        if iface_info:
            for ap in results:
                if ap.bssid == iface_info.get("bssid"):
                    ap.is_connected = True
                    ap.band = iface_info.get("band") or ap.band
                    ap.rx_rate = iface_info.get("rx_rate") or ap.rx_rate
                    ap.tx_rate = iface_info.get("tx_rate") or ap.tx_rate
                    if iface_info.get("channel"):
                        ap.channel = iface_info["channel"]
                    if iface_info.get("signal"):
                        ap.signal = iface_info["signal"]
                    break
            else:
                results.append(
                    AccessPoint(
                        ssid=iface_info.get("ssid") or "<current>",
                        bssid=iface_info.get("bssid") or "",
                        channel=iface_info.get("channel"),
                        signal=iface_info.get("signal"),
                        security=normalize_security(iface_info.get("auth") or "unknown"),
                        band=iface_info.get("band"),
                        rx_rate=iface_info.get("rx_rate"),
                        tx_rate=iface_info.get("tx_rate"),
                        data_rate=None,
                        last_seen=now,
                        is_connected=True,
                        captive_redirect=None,
                    )
                )
        return results

    def current_interface(self):
        proc = run_command(["netsh", "wlan", "show", "interfaces"])
        info = {}
        connected = None
        for line in stdout_lines(proc):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if self.is_state_key(key):
                connected = self.is_connected_state(value)
            elif self.is_ssid_key(key):
                info["ssid"] = value
            elif self.is_bssid_key(key):
                info["bssid"] = self.extract_mac(value.lower())
            elif self.is_channel_key(key) and value.isdigit():
                info["channel"] = int(value)
            elif self.is_signal_key(key):
                num = value.replace("%", "").strip()
                if num.isdigit():
                    info["signal"] = int(num)
            elif self.is_auth_key(key):
                info["auth"] = value
            elif self.is_receive_rate_key(key):
                rate = self.extract_float(value)
                if rate is not None:
                    info["rx_rate"] = rate
            elif self.is_transmit_rate_key(key):
                rate = self.extract_float(value)
                if rate is not None:
                    info["tx_rate"] = rate
            elif self.is_radio_type_key(key):
                if "5ghz" in value.lower() or "802.11a" in value.lower():
                    info["band"] = "5 GHz"
                elif "6ghz" in value.lower():
                    info["band"] = "6 GHz"
                elif "2.4ghz" in value.lower() or "802.11b" in value.lower() or "802.11g" in value.lower():
                    info["band"] = "2.4 GHz"
        if info.get("channel") and not info.get("band"):
            info["band"] = channel_to_band(info["channel"])
        if connected is False:
            return None
        return info or None

    def is_ssid_line(self, line):
        stripped = line.strip().lower()
        return stripped.startswith("ssid ") and "bssid" not in stripped

    def is_bssid_line(self, line):
        return line.strip().lower().startswith("bssid")

    def is_signal_line(self, line):
        lowered = line.strip().lower()
        return lowered.startswith("signal") or lowered.startswith("сигнал")

    def is_auth_line(self, line):
        lowered = line.strip().lower()
        return lowered.startswith("authentication") or lowered.startswith("проверка подлинности")

    def is_channel_line(self, line):
        lowered = line.strip().lower()
        return lowered.startswith("channel") or lowered.startswith("канал")

    def is_state_key(self, key):
        return key == "state" or key == "состояние"

    def is_connected_state(self, value):
        lowered = value.strip().lower()
        return lowered in ("connected", "подключено", "подключен")

    def is_ssid_key(self, key):
        return key == "ssid" or key == "имя ssid"

    def is_bssid_key(self, key):
        return key == "bssid"

    def is_channel_key(self, key):
        return key == "channel" or key == "канал"

    def is_signal_key(self, key):
        return key == "signal" or key == "сигнал"

    def is_auth_key(self, key):
        return key == "authentication" or key == "проверка подлинности"

    def is_receive_rate_key(self, key):
        return key.startswith("receive rate") or key.startswith("скорость приема")

    def is_transmit_rate_key(self, key):
        return key.startswith("transmit rate") or key.startswith("скорость передачи")

    def is_radio_type_key(self, key):
        return key == "radio type" or key == "тип радиомодуля"

    def extract_mac(self, value):
        match = MAC_RE.search((value or "").lower())
        if match:
            return match.group(0).replace("-", ":")
        return value.lower().replace("-", ":")

    def extract_float(self, value):
        match = re.search(r"\d+([.,]\d+)?", value)
        if not match:
            return None
        return float(match.group(0).replace(",", "."))


def get_scanner():
    system = platform.system().lower()
    if system == "darwin":
        return MacScanner()
    if system == "windows":
        return WindowsScanner()
    return LinuxScanner()


def disconnect_wifi():
    system = platform.system().lower()
    try:
        if system == "darwin":
            run_command(["networksetup", "-setairportpower", "en0", "off"])
        elif system == "linux":
            run_command(["nmcli", "radio", "wifi", "off"])
        elif system == "windows":
            interface_names = windows_wifi_interface_names()
            if interface_names:
                for iface in interface_names:
                    run_command(["netsh", "wlan", "disconnect", f"interface={iface}"])
                for iface in interface_names:
                    run_command(["netsh", "interface", "set", "interface", iface, "admin=disabled"])
            else:
                run_command(["netsh", "wlan", "disconnect"])
                for iface in ("Wi-Fi", "Wireless Network Connection", "Беспроводная сеть"):
                    run_command(["netsh", "interface", "set", "interface", iface, "admin=disabled"])
    except Exception:
        pass


def windows_wifi_interface_names():
    try:
        proc = run_command(["netsh", "wlan", "show", "interfaces"])
    except Exception:
        return []
    names = []
    for line in stdout_lines(proc):
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in ("name", "имя") and value:
            names.append(value)
    seen = set()
    ordered = []
    for name in names:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def probe_captive_redirect(timeout_sec=4):
    try:
        proc = run_command(["curl", "-I", "-L", "--max-time", str(timeout_sec), "https://www.google.com"], timeout=timeout_sec + 1)
    except FileNotFoundError:
        return None
    except Exception:
        return None
    if not proc.stdout:
        return None
    for line in stdout_lines(proc):
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
            if LOCAL_IP_RE.search(loc):
                return True
    return False


def get_gateway_oui():
    system = platform.system().lower()
    mac = None
    try:
        if system == "darwin":
            mac = mac_from_arp(gateway_ip_darwin())
        elif system == "linux":
            mac = mac_from_arp(gateway_ip_linux())
        elif system == "windows":
            mac = mac_from_arp(gateway_ip_windows())
    except Exception:
        mac = None
    if mac and MAC_RE.match(mac.lower()):
        return ":".join(mac.lower().replace("-", ":").split(":")[:3])
    return None


def mac_from_arp(ip):
    if not ip:
        return None
    system = platform.system().lower()
    try:
        if system == "darwin":
            proc = run_command(["arp", "-n", ip])
        elif system == "linux":
            proc = run_command(["ip", "neigh", "show", ip])
            if not (proc.stdout or "").strip():
                proc = run_command(["arp", "-n", ip])
        else:
            proc = run_command(["arp", "-a", ip])
    except Exception:
        return None
    match = MAC_RE.search((proc.stdout or "").lower())
    if match:
        return match.group(0)
    return None


def gateway_ip_darwin():
    try:
        proc = run_command(["route", "-n", "get", "default"])
        for line in stdout_lines(proc):
            if "gateway:" in line:
                return line.split("gateway:", 1)[1].strip()
    except Exception:
        return None
    return None


def gateway_ip_linux():
    try:
        proc = run_command(["ip", "route", "show", "default"])
        for line in stdout_lines(proc):
            parts = line.split()
            if parts and parts[0] == "default":
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
    except Exception:
        return None
    return None


def gateway_ip_windows():
    try:
        proc = run_command(["netsh", "interface", "ip", "show", "addresses"])
        for line in stdout_lines(proc):
            if "Default Gateway" in line and ":" in line:
                candidate = line.split(":", 1)[1].strip()
                if candidate:
                    return candidate
    except Exception:
        return None
    return None
