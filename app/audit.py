from datetime import datetime, timezone

SEVERITY_POINTS = {"Critical": 35, "High": 20, "Medium": 10, "Low": 3, "Info": 0}

def audit_networks(networks):
    """Create evidence-backed defensive findings and risk scores from observed wireless metadata."""
    audited = []
    
    # Pre-index SSIDs to detect duplicate SSID anomalies (Evil Twin / Rogue AP signature)
    ssid_map = {}
    for n in networks:
        s = str(n.get("ssid") or "").strip()
        if s and s != "(hidden SSID)":
            ssid_map.setdefault(s, []).append(n)

    for raw in networks:
        network = dict(raw)
        security = str(network.get("security") or "Unknown").strip()
        sec_upper = security.upper()
        cipher = str(network.get("cipher") or "").strip().upper()
        ssid = str(network.get("ssid") or "").strip()
        is_conn = bool(network.get("is_connected", False))
        findings = []

        # 1. Open / Unencrypted Network
        if sec_upper in {"OPEN", "NONE", "--", ""} or cipher in {"NONE", "OPEN"}:
            sev = "Critical" if is_conn else "High"
            findings.append({
                "id": "WIFI-001",
                "title": "Open Unencrypted Wireless Network",
                "severity": sev,
                "confidence": "High",
                "evidence": f"Advertised security: {security or 'OPEN'}, Cipher: {cipher or 'None'}. No link-layer encryption enabled.",
                "impact": "Anyone within radio range can monitor unencrypted plaintext, capture session tokens, inspect DNS requests, or execute Man-in-the-Middle (MitM) attacks.",
                "recommendation": "Configure router to enforce WPA3-Personal or WPA2-AES (CCMP). If connecting to this network on the host, always route all traffic through a secure, encrypted VPN tunnel."
            })

        # 2. Obsolete WEP
        elif "WEP" in sec_upper or "WEP" in cipher:
            findings.append({
                "id": "WIFI-002",
                "title": "Legacy WEP Encryption Advertised",
                "severity": "Critical",
                "confidence": "High",
                "evidence": f"Advertised security: {security}, Cipher: {cipher}.",
                "impact": "WEP uses RC4 with weak 24-bit initialization vectors (IVs). Keys can be recovered deterministically in minutes using statistical packet analysis.",
                "recommendation": "Immediately decommission WEP. Replace legacy hardware or reconfigure AP with WPA3-Personal or WPA2-AES."
            })

        # 3. Deprecated WPA1 or TKIP
        elif (("WPA" in sec_upper and "WPA2" not in sec_upper and "WPA3" not in sec_upper) or "TKIP" in cipher):
            findings.append({
                "id": "WIFI-003",
                "title": "Deprecated WPA1 / TKIP Mode Advertised",
                "severity": "High",
                "confidence": "High",
                "evidence": f"Advertised security: {security}, Cipher: {cipher}.",
                "impact": "TKIP was deprecated by the Wi-Fi Alliance in 2012 due to Beck-Tews and Michael MIC key recovery vulnerabilities.",
                "recommendation": "Disable TKIP and WPA1 support on the wireless access point. Mandate WPA2-AES (CCMP) or WPA3-Personal (SAE)."
            })

        # 4. Unknown Security Mode
        elif sec_upper in {"UNKNOWN", ""}:
            findings.append({
                "id": "WIFI-004",
                "title": "Security Mode Could Not Be Determined",
                "severity": "Info",
                "confidence": "Low",
                "evidence": "Discovery source did not report recognized authentication flags.",
                "impact": "Network cannot be audited with confidence from beacon metadata alone.",
                "recommendation": "Check the router administrative interface to confirm encryption settings."
            })

        # 5. Hidden SSID
        if ssid in {"(hidden SSID)", "", "<hidden>"}:
            findings.append({
                "id": "WIFI-006",
                "title": "Hidden SSID (Cloaked Network)",
                "severity": "Medium",
                "confidence": "High",
                "evidence": "Access point suppresses SSID broadcast in 802.11 beacon frames.",
                "impact": "SSID cloaking provides false security; connected clients actively broadcast probe requests everywhere they travel, leaking historical connection names.",
                "recommendation": "Broadcast SSID normally and rely on WPA3/WPA2 with strong passphrases rather than obscurity."
            })

        # 6. WPA2-Personal (PSK) without WPA3
        if "WPA2" in sec_upper and "WPA3" not in sec_upper and not any(f["id"] == "WIFI-003" for f in findings):
            findings.append({
                "id": "WIFI-007",
                "title": "WPA2-Personal Standard (PSK Handshake)",
                "severity": "Low",
                "confidence": "Medium",
                "evidence": f"Advertised security: {security}, Cipher: {cipher or 'CCMP'}.",
                "impact": "WPA2 4-way handshakes and PMKID can be captured passively and subjected to offline dictionary/hash cracking. Does not enforce Protected Management Frames (802.11w) by default, leaving clients susceptible to deauthentication DoS.",
                "recommendation": "Upgrade to WPA3-Personal (SAE) for forward secrecy and offline dictionary resistance. If using WPA2, enforce passphrases longer than 18 characters and enable Protected Management Frames (PMF)."
            })

        # 7. WPA3 Hardened Wireless Security
        if "WPA3" in sec_upper:
            findings.append({
                "id": "WIFI-008",
                "title": "Modern WPA3 Hardened Wireless Security Active",
                "severity": "Info",
                "confidence": "High",
                "evidence": f"Advertised security: {security}. Simultaneous Authentication of Equals (SAE) enabled.",
                "impact": "Protects against offline dictionary attacks, enforces forward secrecy, and requires Protected Management Frames (802.11w) to block deauthentication attacks.",
                "recommendation": "Maintain latest firmware updates. Disable legacy transition mode if all connecting devices support pure WPA3."
            })

        # 8. Potential Evil Twin / Rogue AP Anomaly
        if ssid and len(ssid_map.get(ssid, [])) > 1:
            matching_nets = ssid_map[ssid]
            sec_types = {str(m.get("security", "")).upper() for m in matching_nets}
            if len(sec_types) > 1:
                findings.append({
                    "id": "WIFI-009",
                    "title": "Conflicting Security Profile (Potential Rogue AP / Evil Twin)",
                    "severity": "Critical" if is_conn else "High",
                    "confidence": "Medium",
                    "evidence": f"Multiple access points broadcast SSID '{ssid}' with conflicting security types: {', '.join(sec_types)}.",
                    "impact": "An attacker may be operating a Rogue AP / Evil Twin honeypot with lower security to trick devices into connecting and leaking credentials.",
                    "recommendation": "Verify the BSSID MAC address with your network administrator. Avoid connecting until access points are verified."
                })

        # 9. Weak Signal
        signal = network.get("signal")
        if isinstance(signal, (int, float)) and signal < 20:
            findings.append({
                "id": "WIFI-005",
                "title": "Weak Received Signal Level",
                "severity": "Info",
                "confidence": "Medium",
                "evidence": f"Reported signal strength: {signal}%.",
                "impact": "Prone to high packet error rates and connection drops.",
                "recommendation": "Adjust antenna orientation or reduce distance to access point."
            })

        # Calculate risk score (0 to 100)
        score = sum(SEVERITY_POINTS.get(f["severity"], 0) for f in findings)
        # Clean WPA3 with no vulnerabilities has 0 risk
        if "WPA3" in sec_upper and not any(f["severity"] in ("Critical", "High", "Medium") for f in findings):
            score = 0
        # If connected to an open/vulnerable network, increase risk score
        if is_conn and any(f["severity"] in ("Critical", "High") for f in findings):
            score = min(100, score + 15)

        score = min(100, score)
        
        # Risk label & Security Grade
        if score >= 40:
            risk_label = "Critical"
            grade = "F"
        elif score >= 25:
            risk_label = "High"
            grade = "D"
        elif score >= 10:
            risk_label = "Moderate"
            grade = "C"
        elif score > 0:
            risk_label = "Low"
            grade = "B"
        else:
            risk_label = "Safe"
            grade = "A"

        network["findings"] = findings
        network["risk_score"] = score
        network["risk_label"] = risk_label
        network["security_grade"] = grade
        network["audited_at"] = datetime.now(timezone.utc).isoformat()
        audited.append(network)

    return audited
