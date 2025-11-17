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
    "rule_name"
]

# Ports commonly associated with web & file transfer
HIGH_RISK_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".sh"]
SUSPICIOUS_PORTS = [21, 22, 23, 445, 3389]  # FTP, SSH, Telnet, SMB, RDP

# Thresholds for simple heuristics
MIN_BYTES_FOR_DOWNLOAD = 50_000          # adjust based on dataset
MIN_CONNECTIONS_FOR_BEACON = 5           # same dst in a short timeframe
