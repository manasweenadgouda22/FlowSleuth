# FlowSleuth – Project Report Outline

## 1. Introduction
- Background on network forensics and outbound threat detection.
- Motivation: why focusing on *outgoing* connections matters (exfiltration, C2, malware downloads).
- Problem statement and scope of FlowSleuth.

## 2. Literature Review
- Traditional PCAP/NetFlow analysis in DFIR.
- Router / firewall log analysis in incident response.
- Existing tools (Wireshark, Zeek, Suricata, SIEM platforms).
- Gaps: lack of lightweight, student-friendly correlation tools with visualization.

## 3. System Design
- Overall architecture diagram (workstation → router → firewall → FlowSleuth).
- Data sources and formats (flow CSV, firewall CSV).
- Threat-intel enrichment design.

## 4. Implementation
- Technologies: Python, pandas, Streamlit.
- Detailed explanation of the analysis pipeline:
  - Flow ingestion and normalization.
  - Heuristic-based suspicious download detection.
  - Beaconing detection with rolling windows.
  - Correlation with firewall logs.
  - Threat-score assignment.
- Dashboard features and UI design.

## 5. Experiments & Evaluation
- Test scenarios:
  - Benign browsing vs. malicious download attempts.
  - Simulated beaconing to a suspicious IP.
- Metrics:
  - Number of true suspicious flows detected.
  - False positives/negatives (qualitative discussion).
- Screenshots of the dashboard with commentary.

## 6. Discussion
- Strengths and limitations of heuristic-based detection.
- How the framework could be enhanced with ML.
- Operational considerations in a SOC or blue-team environment.

## 7. Conclusion & Future Work
- Summary of contributions.
- Ideas for future enhancements (ML, cloud deployment, integration with Zeek, Suricata, or SIEM).

## 8. References
- Cite textbooks, academic papers, and documentation you used.
