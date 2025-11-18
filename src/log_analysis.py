import pandas as pd
from src.config import FIREWALL_REQUIRED_COLUMNS

def load_firewall_logs(file):
    name = file.name.lower()

    if name.endswith(".csv"):
        df = pd.read_csv(file)
    elif name.endswith(".xlsx") or name.endswith(".xls"):
        df = pd.read_excel(file)
    else:
        raise ValueError("Unsupported file format. Upload CSV or Excel (.xlsx)")

    missing = [c for c in FIREWALL_REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing firewall log columns: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df
