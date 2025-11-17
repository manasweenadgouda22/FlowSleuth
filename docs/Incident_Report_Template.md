# FlowSleuth – Incident Report Template

**Incident ID:** FS-IR-001  
**Date/Time Opened:**  
**Handler:** Manaswee Balvant Nadgouda  

## 1. Executive Summary
Briefly describe what happened, when it was detected, and current status.

## 2. Detection
- Tool: FlowSleuth (dashboard / script).
- Indicators:
  - Suspicious outbound flow(s) to IP(s): ...
  - Port(s): ...
  - Threat levels: ...

## 3. Scope & Impact
- Affected host(s) / subnet(s).
- Potential data accessed or exfiltrated.
- Business and security impact.

## 4. Evidence Collected
- Flow CSV (PCAP-derived).
- Firewall/router logs.
- Screenshots from FlowSleuth dashboard.
- Any additional logs (EDR, AV, OS logs).

## 5. Timeline
- T0 – First suspicious connection detected.
- T1 – Alert triaged in FlowSleuth.
- T2 – Containment actions.
- T3 – Eradication and recovery.

## 6. Root Cause
- Initial access vector (if known).
- Malware / tool used (if applicable).
- Misconfigurations exploited.

## 7. Containment, Eradication & Recovery
- Steps taken to contain the incident.
- Cleanup actions performed.
- Validation that systems are back to normal.

## 8. Lessons Learned & Recommendations
- What worked well in detection & response.
- Gaps identified (visibility, logging, processes).
- Concrete improvements to implement.

## 9. Appendices
- Full FlowSleuth exports.
- Raw log excerpts.
- Any external reports (e.g., VirusTotal analysis).
