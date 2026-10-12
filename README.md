# WiFiSentinel AI — Wireless Security Assessment

A defensive, local-first Wi-Fi security assessment dashboard. It supports:
- OS metadata discovery (Linux `nmcli`; Windows uses a safe simulated/sample mode unless a collector is added)
- Evidence-based configuration findings and transparent risk scoring
- Demo dataset for immediate evaluation without a wireless adapter
- Assessment history in SQLite
- JSON and PDF report export
- FastAPI backend and a lightweight responsive dashboard

## Safety scope
Use only on networks you own or are explicitly authorized to assess. This project does **not** crack passwords, capture credentials, deauthenticate clients, create rogue access points, or attack third-party networks. Wireless discovery reports advertised metadata; it cannot prove a network is exploitable.

## Quick start (Python 3.11+)
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000

Use **Demo scan** to populate example findings. Choose **Live scan** to collect metadata from the local machine where supported (Linux with `nmcli`). Windows currently returns a clear unsupported-collector message rather than pretending it scanned.

## Project structure
- `app/main.py`: API + serves dashboard
- `app/scanner.py`: safe platform-specific wireless metadata collection
- `app/audit.py`: security rules and risk scoring
- `app/storage.py`: SQLite assessment history
- `app/reports.py`: JSON/PDF exports
- `app/static/index.html`: dashboard UI
- `tests/`: unit tests

## Limitations
- Detection is based on observable advertised security metadata and manually supplied authorized router configuration.
- WPS state, firmware age, admin password strength, client isolation and router patch status generally require authenticated router inspection; the tool will not infer them from SSID alone.
- Treat results as a starting point for a formal audit, not a certification.
