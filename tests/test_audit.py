from app.audit import audit_networks
from app.scanner import demo_networks

def test_demo_audit_flags_open_and_wep():
    result = audit_networks(demo_networks())
    by_ssid = {n["ssid"]: n for n in result}
    assert any(f["id"] == "WIFI-001" for f in by_ssid["Guest-Open-Lab"]["findings"])
    assert any(f["id"] == "WIFI-002" for f in by_ssid["Legacy-Test-Lab"]["findings"])

def test_unknown_is_not_called_vulnerable():
    result = audit_networks([{"ssid":"unknown","security":"Unknown"}])[0]
    assert result["findings"][0]["severity"] == "Info"

def test_secure_wpa2_not_flagged_as_legacy():
    result = audit_networks([{"ssid":"lab","security":"WPA2"}])[0]
    assert not any(f["severity"] in ("High","Critical") for f in result["findings"])
