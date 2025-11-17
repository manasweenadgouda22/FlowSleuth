# FlowSleuth

FlowSleuth is a mini DFIR/network-forensics project that analyzes **suspicious outbound connections**
by correlating packet captures (PCAP metadata), router/firewall logs, and threat‑intelligence lookups.
It also provides a simple **Streamlit dashboard** to visualize suspicious flows for demos and interviews.

## Features

- Upload PCAP metadata (exported as CSV from Wireshark or Zeek) and firewall/router logs.
- Automatically flag suspicious outbound connections:
  - Executable / script downloads (`.exe`, `.dll`, `.ps1`, `.sh`, etc.).
  - Connections to non‑standard ports or uncommon destinations.
  - Repeated beacon‑style connections from the same host.
- Basic threat‑intel enrichment via placeholder hooks (ready for VirusTotal / AbuseIPDB / OTX).
- Streamlit dashboard:
  - Summary KPIs (total flows, unique IPs, # flagged suspicious).
  - Interactive tables of suspicious connections.
  - Simple bar chart of top suspicious destination IPs.
- Designed so you can easily extend it into a **full Master’s project** with:
  - More sophisticated ML‑based anomaly detection.
  - Cloud deployment (e.g., AWS EC2 + S3).
  - Integration with Zeek and Suricata logs.

## Quick Start

1. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Prepare input data:
   - Export Wireshark or Zeek flows as CSV (at minimum: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `bytes`, `timestamp`).
   - Put sample files in the `data/` folder or upload via the Streamlit UI.

4. Run the dashboard:

   ```bash
   streamlit run src/dashboard.py
   ```

5. Open the local URL shown in the console (usually http://localhost:8501) to explore the dashboard.

## Project Structure

```text
FlowSleuth/
├── README.md
├── requirements.txt
├── src/
│   ├── dashboard.py          # Streamlit UI
│   ├── pcap_analysis.py      # PCAP/flow CSV parsing & heuristics
│   ├── log_analysis.py       # Firewall/router log parsing
│   ├── threat_intel.py       # Threat-intel lookup stubs
│   └── config.py             # Simple config & constants
├── data/
│   ├── sample_flows.csv      # Example flow data
│   └── sample_firewall.csv   # Example firewall log
└── docs/
    ├── Project_Report_Outline.md
    └── Incident_Report_Template.md
```

## How to Talk About This in Interviews

- Emphasize that you:
  - Designed the pipeline to **correlate PCAP, router artifacts, and firewall logs**.
  - Built an **interactive dashboard** for triage and visualization.
  - Left clear extension points for **ML‑based anomaly detection** and **threat‑intel enrichment**.
