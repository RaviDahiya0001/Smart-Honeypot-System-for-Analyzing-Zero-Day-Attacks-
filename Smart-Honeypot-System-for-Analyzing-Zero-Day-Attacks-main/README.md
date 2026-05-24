# 🍯 Smart Honeypot System for Analyzing Zero-Day Attacks

A robust, full-featured honeypot monitoring system built with Django. This system simulates vulnerable network services (SSH, FTP, HTTP, Telnet) to attract malicious actors, logs their activities in real-time, and provides detailed analytics and threat intelligence via a glassmorphic dark-mode dashboard.

## ✨ Key Features

- **🛡️ Multi-Protocol Simulation**: Simulates SSH, FTP, HTTP, Telnet, and SMB services to trap attackers.
- **📊 Real-Time Dashboard**: Live attack feed, protocol distribution, and attack timeline using WebSockets (Django Channels).
- **🌍 Interactive Map**: 3D-style world map visualizing attack origins (GeoIP integrated).
- **🤖 Threat Intelligence**: Automated threat scoring, IP reputation analysis, and pattern detection.
- **📈 Advanced Reporting**: Export logs to CSV/JSON/PDF and generate executive summaries.
- **🔒 Security Controls**: IP blacklisting, rate limiting, and honeypot isolation mechanisms.

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Redis (for Celery and Channels)

### 1. Installation

1.  **Clone the repository**:
    ```bash
    git clone <repository_url>
    cd smart-honeypot
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Apply database migrations**:
    ```bash
    python manage.py migrate
    ```

4.  **Create a superuser** (for accessing the dashboard admin):
    ```bash
    python manage.py createsuperuser
    ```

### 2. Running the System

You need to run the Django server (Dashboard) and the Honeypot Services (Sensors).

#### Start the Dashboard (and WebSockets)
```bash
python manage.py runserver
```
Access the dashboard at: **http://127.0.0.1:8000/**

#### Start Honeypot Services
In a separate terminal, launch the services:
```bash
python manage.py run_honeypot
```
*Note: Bind permission for ports < 1024 may require elevated privileges (sudo/Administrator).*

#### Start Celery Worker (Optional, for reports)
```bash
celery -A honeypot worker -l info
```

### 3. Usage & Simulation

**🧪 Demo Data**:
To verify the dashboard without waiting for real attacks, populate it with simulated data:
```bash
python manage.py populate_data
```

**⚔️ Simulating Attacks**:
You can test the system by "attacking" yourself:
```bash
# SSH Attack
ssh -p 2222 admin@localhost

# Web Attack (Blind SQL Injection)
curl "http://localhost:8080/search?q=1' OR '1'='1"

# FTP Access
ftp localhost 2121
```

## 📂 Project Structure

- **`dashboard/`**: Core Django app. Handles UI, Views, Models, and WebSocket consumers.
- **`services/`**: The honeypot sensor logic (SSH, FTP, etc.) using `asyncio` and `socket`.
- **`analyzer/`**: Logic for detecting patterns, anomalies, and generating threat reports.
- **`utils/`**: Helper modules for geolocation, encryption, and rate limiting.
- **`honeypot/`**: Project configuration (settings, ASGI/WSGI, URLs).

## 🛠️ Tech Stack

- **Backend**: Django 5.0, Python 3.10
- **Real-time**: Django Channels (WebSockets), Redis
- **Frontend**: HTML5, CSS3 (Glassmorphism), JavaScript
- **Visualization**: Chart.js, Leaflet.js, Three.js
- **Database**: SQLite (Dev) / PostgreSQL (Prod)

## ⚠️ Security Warning

**DO NOT DEPLOY ON A PRODUCTION NETWORK WITHOUT ISOLATION.**
This system is designed to attract attackers. Deploy it in a secure, isolated environment (e.g., a dedicated VM, VPS, or DMZ subnet) to prevent lateral movement.

---
*Created for Advanced Threat Analysis Project*
