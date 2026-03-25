# AegisNet — Intelligent Network Security Monitoring Platform

![AegisNet](https://img.shields.io/badge/AegisNet-v1.0.0-00d4ff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey?style=for-the-badge&logo=flask)
![MySQL](https://img.shields.io/badge/MySQL-8.0-orange?style=for-the-badge&logo=mysql)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> A real-time network traffic monitoring and intrusion detection platform designed for schools, companies, and institutions.

---

## 🔐 What is AegisNet?

AegisNet is a lightweight yet powerful **Network Intrusion Detection System (NIDS)** that continuously monitors network traffic, detects suspicious activities, identifies connected devices, and alerts administrators through a real-time web-based dashboard.

It is designed to provide professional network security visibility without the complexity of enterprise tools like Snort or Suricata — making it ideal for small organizations, training institutions, and schools.

---

## 🚀 Live Features

| Feature | Description |
|---|---|
| 🌐 **Live Packet Capture** | Captures and analyzes every packet on the network in real time |
| 🔍 **Intrusion Detection** | Detects port scans, brute force attempts, and DDoS traffic floods |
| 💻 **Device Discovery** | Automatically scans and identifies all devices connected to the network |
| 🗺️ **Network Topology Map** | Visual interactive map of all connected devices |
| 🚫 **IP Blocking** | Block suspicious IPs directly from the dashboard with firewall integration |
| 📊 **Real-Time Dashboard** | Live charts, packet feed, alerts and device tables |
| ❤️ **System Health Monitor** | CPU, memory, disk and network I/O monitoring |
| 👥 **User Management** | Add and manage multiple admin accounts |
| 📧 **Email Alerts** | Automatic email notifications when threats are detected |
| 📄 **PDF Security Reports** | Generate and download professional security reports |
| 📁 **CSV Export** | Export packets, devices, alerts and blocked IPs as CSV |
| ⚙️ **Settings Page** | Configure detection thresholds and change admin password |
| 📱 **Mobile Responsive** | Fully responsive design for phones and tablets |

---

## 🖥️ Screenshots

### Landing Page
The professional product homepage shown to visitors before login.

### Dashboard
Real-time monitoring dashboard showing live packets, devices, alerts and system health.

### Network Topology Map
Interactive visual map showing all connected devices and their relationship to the gateway.

### Settings Page
Configure detection thresholds, change passwords and understand threat types.

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3, Flask, Flask-SocketIO |
| **Packet Capture** | Scapy, Npcap |
| **Threat Detection** | Custom Python detection engine |
| **Database** | MySQL 8.0, PyMySQL |
| **Frontend** | HTML5, CSS3, JavaScript, Bootstrap 5 |
| **Charts** | Chart.js |
| **PDF Reports** | ReportLab |
| **Network Scanning** | Python-nmap |
| **System Monitoring** | psutil |

---

## ⚙️ Installation

### Prerequisites

- Windows 10/11 (64-bit)
- Python 3.10 or higher
- MySQL 8.0
- Npcap (for packet capture)

### Step 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/aegisnet.git
cd aegisnet
```

### Step 2 — Install Npcap

Download and install Npcap from:
👉 https://npcap.com/#download

During installation, enable **WinPcap API-compatible Mode**.

### Step 3 — Install Python Dependencies

```bash
pip install scapy flask flask-socketio pymysql python-nmap psutil reportlab
```

### Step 4 — Set Up the Database

Open MySQL and run:

```sql
CREATE DATABASE aegisnet;
USE aegisnet;

CREATE TABLE network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(50),
    dst_ip VARCHAR(50),
    protocol VARCHAR(20),
    packet_size INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE connected_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(50),
    mac_address VARCHAR(100),
    device_name VARCHAR(100),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME,
    status VARCHAR(20) DEFAULT 'active'
);

CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(100),
    src_ip VARCHAR(50),
    description TEXT,
    severity VARCHAR(20),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(50) UNIQUE,
    reason VARCHAR(200),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE,
    password VARCHAR(200),
    role VARCHAR(20) DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE,
    setting_value VARCHAR(200)
);

INSERT INTO users (username, password, role) VALUES ('admin', 'aegisnet123', 'superadmin');

INSERT INTO settings (setting_key, setting_value) VALUES
('packet_threshold', '100'),
('time_window', '10'),
('port_scan_threshold', '10'),
('port_scan_window', '5'),
('brute_force_threshold', '5'),
('brute_force_window', '10');
```

### Step 5 — Configure Database Connection

Open `backend/config.py` and update with your MySQL credentials:

```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_password',
    'database': 'aegisnet',
    'charset': 'utf8'
}
```

### Step 6 — Run AegisNet

Open **Command Prompt as Administrator** and run:

```bash
cd backend
python app.py
```

Then open your browser and go to:

```
http://localhost:5000
```

### Default Login Credentials

| Field | Value |
|---|---|
| Username | admin |
| Password | aegisnet123 |

> ⚠️ Change your password immediately after first login in the Settings page.

---

## 📁 Project Structure

```
AegisNet/
├── backend/
│   ├── app.py                  # Main Flask application
│   ├── config.py               # Database configuration
│   ├── database.py             # Database functions
│   ├── packet_capture.py       # Network packet capture engine
│   └── detection_engine.py     # Threat detection logic
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css       # Global stylesheet
│   │   └── js/
│   │       └── dashboard.js    # Dashboard JavaScript
│   └── templates/
│       ├── landing.html        # Product landing page
│       ├── login.html          # Admin login page
│       ├── dashboard.html      # Main monitoring dashboard
│       ├── topology.html       # Network topology map
│       ├── users.html          # User management page
│       └── settings.html       # Settings page
└── database/
    └── schema.sql              # Database schema
```

---

## 🔒 Threat Detection

AegisNet detects the following threat types:

| Threat | Description | Severity |
|---|---|---|
| **Port Scan** | A device rapidly scanning multiple ports | High |
| **Brute Force** | Repeated connection attempts to auth ports | Critical |
| **Traffic Flood** | Excessive packets from a single IP (DDoS) | High |

All threats are automatically logged, displayed on the dashboard, and can trigger email alerts.

---

## 🌍 Use Cases

- **Schools and Universities** — Monitor student network activity and detect unauthorized access
- **Training Institutions** — Protect institutional networks from internal and external threats
- **Small Companies** — Affordable network security monitoring without enterprise complexity
- **Internet Cafes** — Monitor connected devices and detect suspicious behavior
- **Home Networks** — Advanced home network security monitoring

---

## 📊 Detection Thresholds (Configurable)

All thresholds can be adjusted from the Settings page:

| Setting | Default | Description |
|---|---|---|
| Packet Threshold | 100 | Packets per IP before flood alert |
| Time Window | 10s | Window for traffic flood detection |
| Port Scan Threshold | 10 | Ports scanned before alert |
| Port Scan Window | 5s | Window for port scan detection |
| Brute Force Threshold | 5 | Attempts before brute force alert |
| Brute Force Window | 10s | Window for brute force detection |

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

Built with 🔐 by **[Your Name]**
- GitHub: [@yourusername](https://github.com/yourusername)

---

## 🤝 Contributing

Contributions, issues and feature requests are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add NewFeature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

> AegisNet — Protecting networks, one packet at a time. 🔐
