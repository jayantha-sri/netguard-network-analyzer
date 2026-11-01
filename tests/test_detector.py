
import pandas as pd
import pytest

from detector import analyze_traffic


def test_detects_watched_port():
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-01T09:00:00Z",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "dst_port": 22,
            "protocol": "TCP",
            "packets": 10
        } 
    ])

    traffic, alerts = analyze_traffic(df)

    assert len(traffic) == 1
    assert "Watched destination port" in alerts["rule"].values


def test_missing_columns():
    df = pd.DataFrame([
        {"src_ip": "192.168.1.10"}
    ])

    with pytest.raises(ValueError):
        analyze_traffic(df)


def test_empty_alerts():
    df = pd.DataFrame([
        {
            "timestamp": "2026-11-01T09:00:00Z",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "dst_port": 443,
            "protocol": "TCP",
            "packets": 10
        }
    ])

    traffic, alerts = analyze_traffic(df)

    assert len(traffic) == 1
    assert alerts.empty
