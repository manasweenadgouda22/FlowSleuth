"""Configuration and constants for FlowSleuth DFIR."""

# Flow record required schema
FLOW_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes"
]

# Firewall log required schema
FIREWALL_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "action",     # ALLOW/BLOCK
    "rule_name"
]

# Suspicious indicators
HIGH_RISK_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".sh"]
SUSPICIOUS_PORTS = [21, 22, 23, 445, 3389]  # FTP/SSH/Telnet/SMB/RDP

# Detection thresholds
MIN_BYTES_FOR_DOWNLOAD = 50_000
MIN_CONNECTIONS_FOR_BEACON = 5
