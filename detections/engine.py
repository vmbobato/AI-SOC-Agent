from typing import List, Dict, Any
import pandas as pd

def _to_df(events: List[Dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(events)
    df["ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["ts"])
    return df

def _window_key(ts: pd.Series, window_minutes: int) -> pd.Series:
    return ts.dt.floor(f"{window_minutes}min")


def detect_web_scans(df, window_minutes, unique_paths_threshold, ratio_404_threshold):
    """
    Web Enumeration Scan:
    - many unique paths in a small time window
    - high 404 ratio
    """
    df = df.copy()
    df["win"] = _window_key(df["ts"], window_minutes)

    grp = df.groupby(["client_ip", "win"])
    rows = []

    for (ip, win), g in grp:
        total = len(g)
        unique_paths = g["path"].nunique()
        ratio_404 = (g["status"] == 404).mean()

        if unique_paths >= unique_paths_threshold and ratio_404 >= ratio_404_threshold:
            # --- severity (simple + explainable) ---
            # bump severity for very high volumes
            if total >= 500:
                severity = "High"
            elif total >= 200:
                severity = "Medium"
            else:
                severity = "Low"

            # --- confidence (simple scoring) ---
            # confidence increases if:
            # - many unique paths above threshold
            # - 404 ratio above threshold
            # - unique paths are a large fraction of total requests (probing behavior)
            unique_ratio = unique_paths / max(1, total)

            score = 0.0
            # base: meets thresholds -> already suspicious
            score += 0.55
            # more unique paths -> more confident (capped)
            score += min(0.25, 0.01 * max(0, unique_paths - unique_paths_threshold))
            # higher 404 ratio above threshold -> more confident (capped)
            score += min(0.15, 0.5 * max(0.0, ratio_404 - ratio_404_threshold))
            # if almost every request is a new path, it screams enumeration
            score += 0.05 if unique_ratio >= 0.9 else 0.0

            confidence = round(min(0.99, max(0.0, score)), 2)

            rows.append({
                "incident_type": "Web Enumeration Scan",
                "timestamp_start": win.isoformat(),
                "timestamp_end": (win + pd.Timedelta(minutes=window_minutes)).isoformat(),
                "source_ips": [ip],
                "evidence": {
                    "requests": total,
                    "unique_paths": int(unique_paths),
                    "unique_ratio": round(float(unique_ratio), 3),
                    "404_ratio": float(ratio_404),
                    "top_paths": g["path"].value_counts().head(10).to_dict(),
                    "status_counts": g["status"].value_counts().to_dict(),
                },
                "severity": severity,
                "confidence": confidence,
                "recommended_actions": [
                    "Block offending IP via AWS WAF (or ALB/WAF) if persistent.",
                    "Enable rate limiting (AWS WAF rate-based rule is ideal).",
                    "Add managed rules / bot protections if available.",
                    "Alert if any scan/probe path returns 200/302 (possible exposure)."
                ],
            })

    return rows


def detect_bruteforce(df, window_minutes, brute_force_threshold):
    df = df.copy()
    df["win"] = _window_key(df["ts"], window_minutes)

    login_paths = [
        "/login",
        "/wp-login.php",
        "/admin",
        "/api/auth",
        "/signin",
    ]

    mask = df["path"].str.contains("|".join(login_paths), na=False)
    login_df = df[mask]

    rows = []
    grp = login_df.groupby(["client_ip", "win"])

    for (ip, win), g in grp:
        attempts = len(g)

        if attempts >= brute_force_threshold:
            fail_ratio = ((g["status"] == 401) | (g["status"] == 403)).mean()

            rows.append({
                "incident_type": "Brute Force Attempt",
                "timestamp_start": win.isoformat(),
                "timestamp_end": (win + pd.Timedelta(minutes=window_minutes)).isoformat(),
                "source_ips": [ip],
                "evidence": {
                    "login_attempts": attempts,
                    "fail_ratio": float(fail_ratio),
                    "top_paths": g["path"].value_counts().head(5).to_dict(),
                },
                "severity": "High",
                "confidence": 0.8,
                "recommended_actions": [
                    "Enable login rate limiting",
                    "Enable MFA",
                    "Block repeated offenders"
                ]
            })

    return rows


def detect_dos_bursts(df, window_minutes, dos_rpm_threshold):
    df = df.copy()
    df["win"] = _window_key(df["ts"], window_minutes)

    window_threshold = dos_rpm_threshold * window_minutes

    rows = []
    grp = df.groupby(["client_ip", "win"])

    for (ip, win), g in grp:
        total = len(g)

        if total >= window_threshold:
            rows.append({
                "incident_type": "Traffic Burst / Possible DoS",
                "timestamp_start": win.isoformat(),
                "timestamp_end": (win + pd.Timedelta(minutes=window_minutes)).isoformat(),
                "source_ips": [ip],
                "evidence": {
                    "requests": total,
                    "top_paths": g["path"].value_counts().head(5).to_dict(),
                },
                "severity": "High",
                "confidence": 0.85,
                "recommended_actions": [
                    "Enable rate limiting",
                    "Block offending IP",
                    "Check server resource usage"
                ]
            })

    return rows


def run_detections(
    events,
    scan_unique_paths_threshold=40,
    scan_404_ratio_threshold=0.85,
    brute_force_threshold=20,
    dos_rpm_threshold=120,
    window_minutes=2,
):
    df = _to_df(events)
    if df.empty:
        return []

    cases = []
    cases.extend(
        detect_web_scans(
            df,
            window_minutes,
            scan_unique_paths_threshold,
            scan_404_ratio_threshold
        )
    )
    cases.extend(
        detect_bruteforce(
            df,
            window_minutes,
            brute_force_threshold
        )
    )
    cases.extend(
        detect_dos_bursts(
            df,
            window_minutes,
            dos_rpm_threshold
        )
    )

    cases.sort(key=lambda c: c.get("timestamp_start", ""))
    return cases