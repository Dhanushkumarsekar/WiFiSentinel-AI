import platform, shutil, subprocess, re

def demo_networks():
    return [
        {"ssid": "Office-Secure-Lab", "bssid": "02:00:00:00:10:01", "security": "WPA2-Personal", "cipher": "CCMP", "signal": 82, "channel": 36, "band": "5 GHz", "radio": "802.11ac", "source": "demo", "is_connected": False},
        {"ssid": "Guest-Open-Lab", "bssid": "02:00:00:00:10:02", "security": "OPEN", "cipher": "None", "signal": 61, "channel": 6, "band": "2.4 GHz", "radio": "802.11n", "source": "demo", "is_connected": False},
        {"ssid": "Legacy-Test-Lab", "bssid": "02:00:00:00:10:03", "security": "WEP", "cipher": "WEP", "signal": 34, "channel": 11, "band": "2.4 GHz", "radio": "802.11b", "source": "demo", "is_connected": False},
        {"ssid": "Executive-WPA3-HQ", "bssid": "02:00:00:00:10:04", "security": "WPA3-Personal", "cipher": "CCMP", "signal": 94, "channel": 48, "band": "5 GHz", "radio": "802.11ax", "source": "demo", "is_connected": True},
        {"ssid": "Unknown-Metadata-Lab", "bssid": "02:00:00:00:10:05", "security": "Unknown", "cipher": None, "signal": 12, "channel": None, "band": None, "radio": None, "source": "demo", "is_connected": False},
    ]

def _parse_windows_interfaces():
    """Extract current active Wi-Fi interface and connection state from Windows netsh."""
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=7,
            check=False
        )
    except Exception:
        return {}

    info = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            if key and val:
                info[key] = val

    state = info.get("State", "").lower()
    return {
        "name": info.get("Name", "Wi-Fi"),
        "description": info.get("Description", "Wireless Network Adapter"),
        "guid": info.get("GUID", ""),
        "mac": info.get("Physical address", ""),
        "state": info.get("State", "disconnected"),
        "is_connected": "connected" in state and "disconnected" not in state,
        "connected_ssid": info.get("SSID", ""),
        "connected_bssid": info.get("AP BSSID", ""),
        "band": info.get("Band", ""),
        "channel": int(info.get("Channel", "0")) if info.get("Channel", "").isdigit() else None,
        "radio": info.get("Radio type", ""),
        "security": info.get("Authentication", ""),
        "cipher": info.get("Cipher", ""),
        "signal": int(info.get("Signal", "").replace("%", "").strip()) if info.get("Signal", "").replace("%", "").strip().isdigit() else None,
        "rssi": info.get("Rssi", ""),
        "receive_rate": info.get("Receive rate (Mbps)", ""),
        "transmit_rate": info.get("Transmit rate (Mbps)", "")
    }

def _scan_windows():
    """Real-time scan on Windows using netsh wlan commands."""
    iface = _parse_windows_interfaces()

    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
            check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Windows wireless network scan timed out.")
    except Exception as e:
        raise RuntimeError(f"Failed to execute Windows Wi-Fi discovery: {e}")

    lines = proc.stdout.splitlines()
    networks = []
    current_net = None
    current_bssid = None

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        m_ssid = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if m_ssid:
            if current_net:
                networks.append(current_net)
            raw_ssid = m_ssid.group(1).strip()
            current_net = {
                "ssid": raw_ssid if raw_ssid else "(hidden SSID)",
                "bssid": None,
                "bssids": [],
                "security": "Unknown",
                "cipher": None,
                "network_type": "Infrastructure",
                "signal": None,
                "channel": None,
                "band": None,
                "radio": None,
                "source": "windows-netsh",
                "is_connected": False
            }
            current_bssid = None
            continue

        if not current_net:
            continue

        if re.search(r"network\s*type", line, re.IGNORECASE):
            current_net["network_type"] = line.split(":", 1)[1].strip()
        elif re.search(r"authentication", line, re.IGNORECASE):
            current_net["security"] = line.split(":", 1)[1].strip()
        elif re.search(r"encryption|cipher", line, re.IGNORECASE):
            current_net["cipher"] = line.split(":", 1)[1].strip()
        elif re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE):
            b_val = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE).group(1).strip()
            current_bssid = {"bssid": b_val, "signal": None, "channel": None, "band": None, "radio": None}
            current_net["bssids"].append(current_bssid)
            if not current_net["bssid"]:
                current_net["bssid"] = b_val
        elif re.search(r"^signal\b", line, re.IGNORECASE):
            val_str = line.split(":", 1)[1].strip().replace("%", "")
            if val_str.isdigit():
                sig = int(val_str)
                if current_bssid:
                    current_bssid["signal"] = sig
                if current_net["signal"] is None or sig > current_net["signal"]:
                    current_net["signal"] = sig
        elif re.search(r"^channel\b", line, re.IGNORECASE):
            val_str = line.split(":", 1)[1].strip()
            if val_str.isdigit():
                ch = int(val_str)
                if current_bssid:
                    current_bssid["channel"] = ch
                if current_net["channel"] is None:
                    current_net["channel"] = ch
        elif re.search(r"^band\b", line, re.IGNORECASE):
            band_str = line.split(":", 1)[1].strip()
            if current_bssid:
                current_bssid["band"] = band_str
            if not current_net["band"]:
                current_net["band"] = band_str
        elif re.search(r"radio\s*type", line, re.IGNORECASE):
            radio_str = line.split(":", 1)[1].strip()
            if current_bssid:
                current_bssid["radio"] = radio_str
            if not current_net["radio"]:
                current_net["radio"] = radio_str

    if current_net:
        networks.append(current_net)

    # Match connected status
    conn_ssid = iface.get("connected_ssid")
    conn_bssid = iface.get("connected_bssid")
    is_connected = iface.get("is_connected")

    found_connected = False
    for n in networks:
        if is_connected and conn_ssid and (n["ssid"] == conn_ssid or (conn_bssid and n.get("bssid") == conn_bssid)):
            n["is_connected"] = True
            found_connected = True
            if iface.get("signal") is not None:
                n["signal"] = iface["signal"]
            if iface.get("channel") is not None:
                n["channel"] = iface["channel"]
            if iface.get("band"):
                n["band"] = iface["band"]
            if iface.get("security") and n.get("security") == "Unknown":
                n["security"] = iface["security"]
            if iface.get("cipher") and not n.get("cipher"):
                n["cipher"] = iface["cipher"]

    # If the system is connected to a network that was hidden or omitted in scan, add it explicitly
    if is_connected and conn_ssid and not found_connected:
        networks.insert(0, {
            "ssid": conn_ssid,
            "bssid": conn_bssid or "00:00:00:00:00:00",
            "bssids": [{"bssid": conn_bssid, "signal": iface.get("signal"), "channel": iface.get("channel"), "band": iface.get("band"), "radio": iface.get("radio")}],
            "security": iface.get("security") or "WPA2",
            "cipher": iface.get("cipher") or "CCMP",
            "network_type": "Infrastructure",
            "signal": iface.get("signal") if iface.get("signal") is not None else 85,
            "channel": iface.get("channel"),
            "band": iface.get("band"),
            "radio": iface.get("radio"),
            "source": "windows-interface",
            "is_connected": True
        })

    # Sort networks: connected first, then descending by signal
    networks.sort(key=lambda x: (not x.get("is_connected", False), -(x.get("signal") or 0)))

    return {
        "supported": True,
        "networks": networks,
        "interface": iface,
        "message": f"Real-time Windows scan found {len(networks)} visible network(s)."
    }

def _scan_linux():
    """Read-only discovery of advertised wireless metadata via nmcli."""
    if not shutil.which("nmcli"):
        return {"supported": False, "networks": [], "message": "nmcli tool is not installed or not in PATH."}

    cmd = ["nmcli", "-f", "IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Unable to list Wi-Fi networks.")
        lines = result.stdout.splitlines()
        if len(lines) <= 1:
            return {"supported": True, "networks": [], "message": "No networks returned by NetworkManager. Ensure Wi-Fi is enabled."}
        
        header = lines[0]
        positions = {key: header.find(key) for key in ("IN-USE", "SSID", "BSSID", "CHAN", "SIGNAL", "SECURITY")}
        networks = []
        for row in lines[1:]:
            try:
                in_use = row[positions["IN-USE"]:positions["SSID"]].strip() if positions.get("IN-USE", -1) != -1 else ""
                ssid = row[positions["SSID"]:positions["BSSID"]].strip() or "(hidden SSID)"
                bssid = row[positions["BSSID"]:positions["CHAN"]].strip()
                channel = row[positions["CHAN"]:positions["SIGNAL"]].strip()
                signal = row[positions["SIGNAL"]:positions["SECURITY"]].strip()
                security = row[positions["SECURITY"]:].strip() or "OPEN"
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": int(channel) if channel.isdigit() else None,
                    "signal": int(signal) if signal.isdigit() else None,
                    "security": security,
                    "source": "nmcli",
                    "is_connected": "*" in in_use
                })
            except (ValueError, IndexError):
                continue
        return {"supported": True, "networks": networks, "message": "Read-only local discovery completed."}
    except subprocess.TimeoutExpired:
        raise RuntimeError("Wi-Fi discovery timed out. Check NetworkManager and Wi-Fi state.")

def _scan_macos():
    """Discovery on macOS using airport utility if available."""
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if shutil.which(airport_path):
        try:
            res = subprocess.run([airport_path, "-s"], capture_output=True, text=True, timeout=10, check=False)
            lines = res.stdout.splitlines()
            networks = []
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        networks.append({
                            "ssid": parts[0],
                            "bssid": parts[1],
                            "signal": max(0, min(100, 2 * (int(parts[2]) + 100))) if parts[2].lstrip("-").isdigit() else None,
                            "channel": int(parts[3].split(",")[0]) if parts[3].split(",")[0].isdigit() else None,
                            "security": parts[6] if len(parts) > 6 else "OPEN",
                            "source": "airport",
                            "is_connected": False
                        })
                return {"supported": True, "networks": networks, "message": "macOS discovery completed."}
        except Exception:
            pass
    return {"supported": False, "networks": [], "message": "macOS live discovery requires the airport CLI tool."}

def live_scan():
    """Real-time discovery of advertised wireless networks and adapter posture across operating systems."""
    system = platform.system().lower()
    if system == "windows":
        return _scan_windows()
    elif system == "linux":
        return _scan_linux()
    elif system == "darwin":
        return _scan_macos()
    return {
        "supported": False,
        "networks": [],
        "message": f"Live wireless scanning is not supported on {platform.system()}. Use Demo scan or manual audit."
    }
