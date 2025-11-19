# 🕵️‍♂️ **FlowSleuth – Network DFIR & Threat Intelligence Dashboard**

**A lightweight Streamlit dashboard for detecting suspicious network activity and enriching logs with threat intelligence.**

FlowSleuth is a hands-on DFIR (Digital Forensics & Incident Response) tool that helps analysts quickly identify hidden threats inside network flow logs. It highlights suspicious downloads, detects beaconing behavior, correlates firewall events, and assigns automated risk scores using simple but realistic heuristics.

This project was built to demonstrate real-world **SOC analysis**, **log parsing**, **threat intel correlation**, and **network forensics** skills—ideal for cybersecurity portfolios, academic work, or DFIR training.

---

## 🎯 **What FlowSleuth Does**

FlowSleuth processes network log data and provides actionable insights:

### ✅ **1. Log Ingestion**

* Accepts **Flow Logs (CSV)**
* Accepts **Firewall Logs (CSV)**
* Validates schema and normalizes timestamps

### ✅ **2. Suspicious Activity Detection**

Flags:

* Large outbound file transfers
* Risky file types (exe, zip, dll)
* High-risk ports (22, 445, 3389)
* Outbound transfers exceeding thresholds

### ✅ **3. Beaconing Detection**

Identifies repeated connections between the same source and destination — common indicators of:

* C2 (Command-and-Control)
* Malware callbacks
* Automated scripts

### ✅ **4. Threat Intelligence Enrichment**

Simulated TI feed adds:

* Known malicious IP matches
* Threat labels
* TI severity scores
* Risk classification (LOW / MEDIUM / HIGH)

### ✅ **5. Firewall Log Correlation**

Shows:

* ALLOW/BLOCK events
* Rule names
* Cross-IP visibility
* Color-coded actions for faster triage

### ✅ **6. Clean, Modern Interface**

Includes:

* Light theme
* Styled file uploaders
* Full-screen layout
* Semantic color coding
* Organized summary panels

---

## 📦 **Data Requirements**

### **1️⃣ Flow Log CSV (Required Columns)**

```
timestamp,src_ip,dst_ip,dst_port,bytes,file_type
```

### **Sample Flow Logs**

```
2025-01-14 10:01,10.0.0.5,185.199.108.153,443,245000,zip
2025-01-14 10:03,10.0.0.8,172.64.150.22,80,180000,exe
2025-01-14 10:04,10.0.0.12,8.8.8.8,22,50000,dll
```

---

### **2️⃣ Firewall Log CSV (Required Columns)**

```
timestamp,src_ip,dst_ip,action
```

### **Sample Firewall Logs**

```
2025-01-14 10:02,10.0.0.5,185.199.108.153,BLOCK
2025-01-14 10:06,10.0.0.8,172.64.150.22,ALLOW
2025-01-14 10:10,10.0.0.12,8.8.8.8,BLOCK
```

---

## 🚀 **How to Run the App**

### **Option A — Run Locally**

```sh
git clone https://github.com/manasweenadgouda22/FlowSleuth.git
cd FlowSleuth
pip install -r requirements.txt
streamlit run src/dashboard.py
```

### **Option B — Streamlit Cloud (Deployed)**

If deployed, your app will run live (insert your URL).

---

## 🧠 **How Detection Works (Simple SOC Logic)**

### 🔎 **Suspicious Download Logic**

* `bytes >= threshold`
* File type in risky list
* Port in suspicious ports list

### 📡 **Beaconing Logic**

* Count repeated src → dst connections
* Flag when repetition exceeds limit

### 🌐 **Threat Intel Matching**

* Matches dst_ip against simulated IOC feed
* Adds TI labels + scores

### 🔥 **Risk Scoring**

Weighted scoring based on:

* TI match
* Large download
* Suspicious port
* Risky file types
* TI score contribution
* Final risk level = LOW / MEDIUM / HIGH

---

## 🗂 **Project Structure**

```
FlowSleuth/
│
├── src/
│   ├── dashboard.py        # Streamlit UI
│   ├── config.py           # Settings + constants
│   ├── pcap_analysis.py    # Flow log detection logic
│   ├── log_analysis.py     # Firewall parser
│   └── threat_intel.py     # Threat enrichment + scoring
│
├── docs/                   # Documentation templates
├── data/                   # Sample CSV files
└── requirements.txt
```

---

## 🧩 **Possible Enhancements**

These can be added anytime:

* PCAP → CSV automatic converter
* Real TI APIs (VirusTotal, GreyNoise, AbuseIPDB)
* GeoIP map visualization
* Full Splunk-style dark theme
* ML anomaly detection
* Export results (CSV/PDF)
* Role-based access

---



📌 **Short portfolio description**
📄 **Resume bullet points (ATS-optimized)**
📣 **LinkedIn announcement post**
🎨 **Logo + branding elements**

Just tell me **“Give portfolio version”** or **“Give resume bullets.”**
