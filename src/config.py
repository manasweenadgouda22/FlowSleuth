FLOW_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "bytes",
    "file_type"
]

FIREWALL_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "action",
    "rule_name"
]

HIGH_RISK_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".sh"]
SUSPICIOUS_PORTS = [21, 22, 23, 445, 3389]

MIN_BYTES_FOR_DOWNLOAD = 50000
MIN_CONNECTIONS_FOR_BEACON = 5
