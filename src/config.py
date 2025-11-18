FLOW_REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "dst_port", "bytes", "file_type"
]

FIREWALL_REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "action", "rule"
]

HIGH_RISK_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".ps1", ".js", ".vbs", ".sh", ".zip", ".rar"
]

SUSPICIOUS_PORTS = [22, 23, 445, 3389, 5900, 8080]

MIN_BYTES_FOR_DOWNLOAD = 150000  # ~150 KB
MIN_CONNECTIONS_FOR_BEACON = 5
