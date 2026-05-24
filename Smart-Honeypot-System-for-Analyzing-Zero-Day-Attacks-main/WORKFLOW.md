# 🔄 Smart Honeypot System - Complete Workflow

This document describes the end-to-end data flow and operational logic of the Smart Honeypot System, from the moment an attacker connects to how the data is visualized on the dashboard.

## 🏗️ System Architecture Overview

The system consists of three main layers:
1.  **Sensor Layer (`services/`)**: Asynchronous honeypot services simulating vulnerable protocols.
2.  **Core Logic Layer (`dashboard/`, `analyzer/`)**: Django backend handling logging, analysis, database storage, and real-time broadcasting.
3.  **Presentation Layer (`templates/`, `static/`)**: The glassmorphic frontend dashboard displaying real-time data.

---

## 🔁 Step-by-Step Attack Lifecycle

### 1. Attacker Connection
*   **Action**: An attacker (or the demo script) connects to a honeypot port (e.g., SSH on port 2222).
*   **Component**: `services/ssh_honeypot.py` (running via `asyncio`).
*   **Result**: The service accepts the TCP connection and presents a fake banner (e.g., `SSH-2.0-OpenSSH_8.2`).

### 2. Activity Logging
*   **Action**: The attacker attempts to log in or run a command.
*   **Component**: `services/base_honeypot.py`.
*   **Logic**:
    1.  Catches the interaction event.
    2.  Resolves IP location using `utils/geolocation.py`.
    3.  Creates a database record:
        *   `Connection` (IP, Protocol, Timestamp)
        *   `LoginAttempt` (Username, Password)
        *   `Command` (if a shell command is executed)

### 3. Real-Time Analysis
*   **Action**: As data is saved, the system checks for threats.
*   **Component**: `analyzer/pattern_detection.py` and `utils/rate_limiter.py`.
*   **Logic**:
    *   **Rate Limiting**: If IP exceeds 100 connections/min -> Add to `IPBlacklist`.
    *   **Pattern Match**: If command matches known malware signature (e.g., `wget`, `curl`) -> Create `Alert` with HIGH severity.

### 4. WebSocket Broadcast
*   **Action**: Notify the dashboard of the new event instantly.
*   **Component**: `dashboard/signals.py` or `models.py` (via `post_save` signals) triggering `dashboard/consumers.py`.
*   **Logic**:
    *   A JSON message containing attack details (IP, Country, Protocol) is sent to the `dashboard` channel group.
    *   `DashboardConsumer` pushes this payload to all connected WebSocket clients.

### 5. Frontend Visualization
*   **Action**: Browser receives the WebSocket message.
*   **Component**: `dashboard/static/js/dashboard.js`.
*   **Logic**:
    *   **Live Feed**: A new row is prepended to the "Recent Attacks" table with a glow effect.
    *   **World Map**: `world-map.js` adds a new marker on the attacker's coordinates.
    *   **Stats**: Counters (Total Connections, etc.) increment automatically.

### 6. Attacker Profiling
*   **Action**: Aggregating data for long-term intelligence.
*   **Component**: `AttackerProfile` model logic.
*   **Result**:
    *   The system creates or updates an `AttackerProfile` for the IP.
    *   Calculates a `Threat Score` based on activity frequency and severity.
    *   This data is viewable on the `/attackers/<ip>/` page.

---

## 🛠️ Operational Workflow

### Starting the System
1.  **Run Database Migrations**: `python manage.py migrate`
2.  **Start Dashboard Server**: `python manage.py runserver` (Handles UI + WebSockets)
3.  **Start Honeypot Services**: `python manage.py run_honeypot` (Starts SSH, FTP, HTTP listeners)

### Monitoring
*   **Admin**: Logs into the dashboard to monitor live attacks.
*   **Alerts**: Receives notifications for critical events (e.g., Zero-Day pattern detected).
*   **Response**: Admin clicks "Blacklist" on a malicious IP -> System drops future connections from that IP.

### Reporting
*   **Periodic**: Celery tasks generate daily PDF summaries.
*   **Manual**: Admin goes to "Reports" page -> Downloads CSV/JSON export of all attack logs.
