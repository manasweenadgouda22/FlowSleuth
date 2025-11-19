
# 🕵️‍♂️ FlowSleuth

### Network DFIR & Threat Intelligence Dashboard

FlowSleuth is an interactive **Streamlit-based DFIR (Digital Forensics & Incident Response) dashboard** designed to help analysts triage potential malicious network activity. The platform ingests **network flow logs** and **firewall logs**, flags suspicious traffic patterns, and enriches findings with **basic threat intelligence indicators**.

This project is intended as an academic and learning-focused tool for students, cybersecurity beginners, and DFIR enthusiasts.

---

## 🎯 Project Objectives

FlowSleuth aims to:

✔ Support rapid investigation of network flow data
✔ Detect suspicious downloads and potentially malicious outbound transfers
✔ Identify repeat beaconing behavior, which may indicate C2 (Command & Control) activity
✔ Enrich suspicious IPs with open threat intelligence feeds (simulated)
✔ Provide structured network visibility for DFIR/Blue Team practice

---

## 🧪 Key Features

| Feature                           | Description                                                      |
| --------------------------------- | ---------------------------------------------------------------- |
| 📥 CSV Upload                     | Accepts **Flow Logs** & **Firewall Logs** (CSV format)           |
| 🚨 Suspicious Activity Detection  | Flags abnormal outbound transfers & risky file types             |
| 📡 Beaconing Detection            | Identifies repeated periodic connections                         |
| 🛡 Firewall Log Viewer            | Displays firewall ALLOW/BLOCK events                             |
| 🌐 Threat Intelligence Enrichment | Simulated enrichment for known malicious IPs/domains             |
| 🎨 Modern UI                      | Styled Streamlit interface for easy use (custom theme supported) |

---

## 📌 Data Requirements

### 1️⃣ Flow Log CSV (Required columns)

| Column name | Type            | Example            |
| ----------- | --------------- | ------------------ |
| `timestamp` | datetime string | `2025-01-14 10:01` |
| `src_ip`    | IPv4            | `10.0.0.5`         |
| `dst_ip`    | IPv4            | `185.199.108.153`  |
| `dst_port`  | integer         | `443`              |
| `bytes`     | integer         | `245000`           |
| `file_type` | string          | `zip`              |

Sample rows:

```csv
timestamp,src_ip,dst_ip,dst_port,bytes,file_type
2025-01-14 10:01,10.0.0.5,185.199.108.153,443,245000,zip
2025-01-14 10:03,10.0.0.8,172.64.150.22,80,180000,exe
```

---

### 2️⃣ Firewall Log CSV (Required columns)

| Column name | Type                   | Example            |
| ----------- | ---------------------- | ------------------ |
| `timestamp` | datetime string        | `2025-01-14 10:02` |
| `src_ip`    | IPv4                   | `10.0.0.5`         |
| `dst_ip`    | IPv4                   | `185.199.108.153`  |
| `action`    | string (`ALLOW/BLOCK`) | `BLOCK`            |

Sample rows:

```csv
timestamp,src_ip,dst_ip,action
2025-01-14 10:02,10.0.0.5,185.199.108.153,BLOCK
2025-01-14 10:06,10.0.0.8,172.64.150.22,ALLOW
```

---

## 🚀 Running the Dashboard

### Option A: Run Locally

#### 1️⃣ Clone the repository

```bash
git clone https://github.com/manasweenadgouda22/FlowSleuth.git
cd FlowSleuth
```

#### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

#### 3️⃣ Launch Streamlit

```bash
streamlit run src/dashboard.py
```

---

### Option B: Run on Streamlit Cloud (Recommended)

The app is deployed at:

🔗 **[https://flowsleuth-](https://flowsleuth-)<your-instance>.streamlit.app**
*(Link may vary based on deployment URL.)*

---

## 🧠 Detection Logic Summary

FlowSleuth uses simple heuristics for learning purposes:

| Detection                | Logic Example                                                  |
| ------------------------ | -------------------------------------------------------------- |
| **Suspicious Downloads** | Large outbound traffic + risky file type (`exe`, `zip`, `dll`) |
| **Beaconing**            | Same `src_ip` → `dst_ip` repeatedly within short intervals     |
| **Threat Intel Match**   | Checks destination IP/domain in simulated IOC list             |

This is **not a production detection engine**, but a practical introduction to network-based DFIR analysis.

---

## 📚 Technologies Used

| Component       | Technology                     |
| --------------- | ------------------------------ |
| UI Framework    | Streamlit                      |
| Processing      | Python (Pandas, Regex)         |
| Visualization   | Streamlit native tables        |
| Threat Intel    | Simulated lookups (extendable) |
| Version Control | Git & GitHub                   |

---

## 📦 Project Structure

```
FlowSleuth/
├── data/                     # Sample CSV files
├── docs/                     # Report templates
├── src/
│   ├── dashboard.py          # Streamlit UI
│   ├── config.py             # Analyzer settings
│   ├── pcap_analysis.py      # Flow processing logic
│   ├── log_analysis.py       # Firewall parser
│   └── threat_intel.py       # Threat enrichment simulation
└── requirements.txt
```

---

## 🧩 Possible Enhancements

🔧 PCAP ingestion + automated CSV transformation
🌐 Real threat intelligence integration (VirusTotal, GreyNoise, AbuseIPDB)
📊 Visualizations: Sankey, GeoIP maps, time-series charts
🧵 Multi-user dashboards with case management
🐍 ML-based anomaly detection

---

## 🏫 Academic Usage & Citation

This project may be referenced in academic coursework and cybersecurity labs. Suggested citation format (APA):

> Nadgouda, M. B. (2025). *FlowSleuth: Network DFIR & Threat Intelligence Dashboard* [Software]. GitHub. [https://github.com/manasweenadgouda22/FlowSleuth](https://github.com/manasweenadgouda22/FlowSleuth)

---



