"""
config.py – central configuration for FlowSleuth
"""

# ---- Required Columns ----
FLOW_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "bytes",
    "file_type",
]

FIREWALL_REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "action",
    "rule_name",
]

# ---- Detection Thresholds / Rules ----
HIGH_RISK_EXTENSIONS = [
    ".exe",
    ".dll",
    ".js",
    ".bat",
    ".ps1",
    ".vbs",
    ".scr",
    ".zip",
    ".rar",
    ".7z",
    ".sh",
]

SUSPICIOUS_PORTS = [22, 23, 135, 139, 445, 3389, 8080]

# Bytes threshold for “big transfer”
MIN_BYTES_FOR_DOWNLOAD = 150_000

# Min connections between same src/dst to treat as beacon-like
MIN_CONNECTIONS_FOR_BEACON = 5

# ---- Tiny built-in threat feed (for demo) ----
# In real life this would come from MISP, VirusTotal, etc.
THREAT_FEED = [
    {
        "indicator": "185.199.108.153",
        "type": "ip",
        "label": "Suspicious GitHub mirror",
        "threat_score": 80,
    },
    {
        "indicator": "45.155.205.25",
        "type": "ip",
        "label": "Known C2 infrastructure",
        "threat_score": 90,
    },
    {
        "indicator": "91.198.174.192",
        "type": "ip",
        "label": "Malicious redirector",
        "threat_score": 75,
    },
]

# ---- Risk scoring (simple weighted model) ----
RISK_WEIGHTS = {
    "ti_match": 50,         # threat intel says it's bad
    "suspicious_port": 20,  # RDP, SMB, etc.
    "big_transfer": 15,     # lots of bytes
    "risky_extension": 15,  # .exe, .dll, .js, …
}

# Risk level thresholds (inclusive ranges)
# risk >= 70  -> HIGH
# 40–69       -> MEDIUM
# < 40        -> LOW
HIGH_RISK_THRESHOLD = 70
MEDIUM_RISK_THRESHOLD = 40

# ---- Very small GeoIP “demo map” ----
# Just enough to make nice charts for your sample data
IP_TO_COUNTRY = {
    "185.199.108.153": "US",
    "172.64.150.22": "US",
    "45.155.205.25": "NL",
    "91.198.174.192": "NL",
    "8.8.8.8": "US",
    "1.1.1.1": "AU",
}
