# 🔍 Web-Based Forensic Log Analyzer (Streamlit)

A powerful **web-based forensic toolkit** for parsing, analyzing, and visualizing custom log files. Built with **Streamlit**, this tool simplifies log analysis for **cybersecurity analysts**, **forensic investigators**, and **IT admins** — offering rich dashboards, anomaly detection, and geo-visualizations with minimal setup

## 🧰 Features

### 📂 Multi-format Log Input

Supports:
- `.vlog`, `.txt`, `.log`, `.csv`

Automatically extracts:
- ⏱️ Timestamps  
- ⚙️ Event types (`EVNT:XR-XXXX`)  
- 👤 Usernames (`usr:username`)  
- 🌐 IP addresses (`IP:xxx.xxx.xxx.xxx`)  
- 📁 File paths (`=>/path`)  
- 🔢 Process IDs (`pidXXXX`)

📈 Visual & Analytical Dashboards

- **📋 Summary Report**: Count of unique users, IPs, event types
- **📅 Event Timeline**: Activity view in 10-second intervals
- **⚠️ Anomaly Detection**:
  - Z-Score (statistical)
  - Isolation Forest (ML-based)
- **🌍 IP Geo-location**:
  - Powered by `ipinfo.io`
  - Interactive map for source IP visualization
