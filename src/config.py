"""Configuration and simple constants for FlowSleuth."""

# File column expectations
FLOW_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes"
]

FIREWALL_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "action",     # ALLOW / BLOCK
    "reason"      # reason or rule explanation for decision
]

# Ports commonly associated with file exfiltration & remote control
SUSPICIOUS_PORTS = [21, 22, 23, 445, 3389, 5900]  # FTP, SSH, Telnet, SMB, RDP, VNC

# High-risk file types for malware delivery
HIGH_RISK_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".ps1", ".sh", ".vbs", ".jar", ".apk"
]

# Thresholds for heuristics
MIN_BYTES_FOR_DOWNLOAD = 50_000          # Minimum size to suspect file transfer
MIN_CONNECTIONS_FOR_BEACON = 5           # Same IP repeated in short intervals
BEACON_TIME_WINDOW_SEC = 120             # Beaconing analysis timeframe
