# SIEM Enterprise v2.0

## Quick Start

```bash
# 1. Start MongoDB (local default: mongodb://localhost:27017/)
#    Optional env: MONGODB_URI, MONGODB_DB (default database: siem_v2)

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the server
python app.py

# 4. Open browser
# http://localhost:5000
# Username: admin
# Password: admin123
```

## Features

- **Real-time event stream** via WebSocket (Socket.IO)
- **Live system metrics** — CPU, Memory, Disk, Network
- **Auto-generated alerts** for high-severity events
- **Incident management** — create, assign, update incidents
- **Threat Hunting** — search events and IOC database
- **Threat Intelligence** — add/manage IOC indicators
- **Compliance tracking** — PCI DSS, SOC 2, ISO 27001, NIST CSF
- **Reports & Export** — JSON/CSV download
- **Detection Rules** — enable/disable rules
- **Event Injection** — test your detection with manual events
- **MITRE ATT&CK mapping** — tactics coverage visualization

## Architecture

- **Backend**: Flask + Flask-SocketIO (Python)
- **Database**: MongoDB (`siem_v2` database, collections auto-seeded on startup)
- **Frontend**: Jinja2 templates, Chart.js, Socket.IO
- **Event Engine**: Multi-threaded background simulation + real psutil system monitoring

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Live overview, charts, event feed |
| Threats | `/threats` | Alerts management |
| Incidents | `/incidents` | IR management |
| Hunting | `/hunting` | Search events & IOCs |
| Compliance | `/compliance` | Framework scores |
| Reports | `/reports` | Trends & export |
| Settings | `/settings` | Rules, injection, system |
