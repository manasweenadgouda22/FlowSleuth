"""Configuration and simple constants for FlowSleuth DFIR."""

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
    "rule_name"
]

# Threat heuristics and detection thresholds
HIGH_RISK_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".sh", ".zip", ".rar"]
SUSPICIOUS_PORTS = [21, 22, 23, 445, 3389, 5900]  # FTP, SSH, Telnet, SMB, RDP, VNC

MIN_BYTES_FOR_DOWNLOAD = 40_000         # Large data downloads
MIN_CONNECTIONS_FOR_BEACON = 5          # Repeated contact with same host
