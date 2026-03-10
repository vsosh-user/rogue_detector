from __future__ import annotations

from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).with_name("data") / "oui_whitelist.txt"


@lru_cache(maxsize=1)
def load_whitelist():
    entries = set()
    if DATA_FILE.exists():
        for line in DATA_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            parts = line.replace("-", ":").split(":")
            if len(parts) >= 3:
                entries.add(":".join(parts[:3]))
    if not entries:
        entries |= {
            "00:1a:1e",
            "00:1b:63",
            "00:1c:bf",
            "00:22:b0",
            "44:94:fc",
            "10:6f:3f",
            "18:64:72",
            "f8:8e:85",
            "d4:6e:0e",
            "b0:4e:26",
            "f4:92:bf",
            "34:36:3b",
            "24:a4:3c",
            "d8:c7:c8",
            "fc:ec:da",
            "dc:2c:6e",
            "3c:84:6a",
            "ac:bc:32",
            "c4:b3:01",
            "d4:2c:44",
            "e4:95:6e",
            "98:4f:ee",
            "f4:3e:61",
            "b0:be:76",
            "14:5a:fc",
            "54:48:e6",
            "ac:3c:0b",
            "f0:18:98",
            "84:fc:ef",
            "e8:2a:44",
            "0c:80:63",
            "1c:87:2c",
            "50:46:5d",
            "64:16:f0",
            "b0:6e:bf",
            "dc:ef:ca",
            "00:1e:58",
            "00:24:01",
            "c0:a0:bb",
            "c8:3a:35",
            "50:64:2b",
            "50:bd:5f",
            "f4:8e:38",
            "44:e0:6e",
            "ec:8a:4c",
            "00:90:8f",
            "54:2a:1b",
            "f0:79:59",
            "00:25:ca",
            "14:da:e9",
            "a4:93:3f",
            "f8:1a:67",
            "08:5a:11",
        }
    return entries


@lru_cache(maxsize=1)
def load_vendor_map():
    vendors = {}
    if DATA_FILE.exists():
        for raw_line in DATA_FILE.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            comment = ""
            if "#" in line:
                line, comment = line.split("#", 1)
                line = line.strip().lower()
                comment = comment.strip()
            parts = line.replace("-", ":").split(":")
            if len(parts) >= 3:
                oui = ":".join(parts[:3])
                if comment:
                    vendors[oui] = comment
    if not vendors:
        vendors = {
            "00:1a:1e": "Cisco",
            "00:1b:63": "Cisco",
            "00:1c:bf": "Cisco",
            "00:22:b0": "Linksys",
            "44:94:fc": "Netgear",
            "10:6f:3f": "TP-Link",
            "18:64:72": "TP-Link",
            "f8:8e:85": "TP-Link",
            "d4:6e:0e": "Mercusys",
            "b0:4e:26": "TP-Link",
            "f4:92:bf": "Ubiquiti",
            "34:36:3b": "Ubiquiti",
            "24:a4:3c": "Ubiquiti",
            "d8:c7:c8": "MikroTik",
            "fc:ec:da": "MikroTik",
            "dc:2c:6e": "MikroTik",
            "3c:84:6a": "Huawei",
            "ac:bc:32": "Huawei",
            "c4:b3:01": "Huawei",
            "d4:2c:44": "Huawei",
            "e4:95:6e": "ZTE",
            "98:4f:ee": "ZTE",
            "f4:3e:61": "ZTE",
            "b0:be:76": "Xiaomi",
            "14:5a:fc": "Xiaomi",
            "54:48:e6": "Xiaomi",
            "ac:3c:0b": "Apple",
            "f0:18:98": "Apple",
            "84:fc:ef": "Apple",
            "e8:2a:44": "ASUS",
            "0c:80:63": "ASUS",
            "1c:87:2c": "ASUS",
            "50:46:5d": "Zyxel",
            "64:16:f0": "Zyxel",
            "b0:6e:bf": "Keenetic",
            "dc:ef:ca": "Zyxel",
            "00:1e:58": "D-Link",
            "00:24:01": "D-Link",
            "c0:a0:bb": "D-Link",
            "c8:3a:35": "Tenda",
            "50:64:2b": "Tenda",
            "50:bd:5f": "Nova",
            "f4:8e:38": "Sagemcom",
            "44:e0:6e": "Sagemcom",
            "ec:8a:4c": "Sagemcom",
            "00:90:8f": "Sercomm",
            "54:2a:1b": "Sercomm",
            "f0:79:59": "Sercomm",
            "00:25:ca": "Eltex",
            "14:da:e9": "Eltex",
            "a4:93:3f": "ZTE/OEM",
            "f8:1a:67": "Huawei/OEM",
            "08:5a:11": "MegaFon",
        }
    return vendors


def get_vendor_name(value):
    if not value:
        return "Неизвестный производитель"
    parts = value.lower().replace("-", ":").split(":")
    if len(parts) < 3:
        return "Неизвестный производитель"
    oui = ":".join(parts[:3])
    return load_vendor_map().get(oui, "Неизвестный производитель")
