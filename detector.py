
import pandas as pd

def analyze_traffic(df):

    required = {
        "timestamp", "src_ip", "dst_ip",
        "dst_port", "protocol", "packets"
    }

    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    df = df.copy()

    df["dst_port"] = pd.to_numeric(
        df["dst_port"], errors="coerce"
    )
    df["packets"] = pd.to_numeric(
        df["packets"], errors="coerce"
    )

    df = df.dropna(
        subset=["src_ip", "dst_ip", "dst_port",
                "protocol", "packets"]
    )

    alerts = []

    counts = df["src_ip"].value_counts()

    for ip, count in counts.items():
        if count >= 20:
            alerts.append({
                "severity": "Medium",
                "source_ip": ip,
                "rule": "High connection-record count"
            })


    watched_ports = [22, 23, 445, 3389]

    for _, row in df.iterrows():
        if row["dst_port"] in watched_ports:
            alerts.append({
                "severity": "Low",
                "source_ip": row["src_ip"],
                "rule": "Watched destination port"
            })

    return df, pd.DataFrame(alerts)
