from typing import List, Dict, Any
import pandas as pd
import re

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

    login_exact = {
    "/login",
    "/login/",
    "/signin",
    "/signin/",
    "/wp-login.php",
    "/api/login",
    "/api/auth/login",
}

    # brute force should usually be POSTs to login endpoints
    mask = (
        df["method"].astype(str).eq("POST")
        & df["path"].astype(str).isin(login_exact)
    )
    login_df = df[mask]
    
    if login_df.empty:
        return []

    rows = []
    grp = login_df.groupby(["client_ip", "win"])

    for (ip, win), g in grp:
        attempts = len(g)

        if attempts >= brute_force_threshold:
            fail_ratio = g["status"].isin([400, 401, 403, 429]).mean()

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

def detect_sensitive_file_probes(df, window_minutes, min_hits=5):
    """
    Detects probing for sensitive files / known exploit targets.
    This is NOT generic scanning; it's specifically 'high-risk target probing'.
    """
    df = df.copy()
    df["win"] = _window_key(df["ts"], window_minutes)

    # Keep this list simple + explainable; you can expand later.
    # Using "contains" on these substrings is intentional.
    indicators = [
        "/.env",
        "/.git/config",
        "/phpinfo",
        "xampp/phpinfo",
        "/vendor/phpunit",
        "eval-stdin.php",
        "/wp-config.php",
        "/adminer",
        "/composer.json",
        "/config.yaml",
        "/id_rsa",
        "/.ssh",
        "/.aws/credentials",
        "/.npmrc",
        "/.docker",
    ]

    path_series = df["path"].astype(str)
    pattern = "|".join(re.escape(x) for x in indicators)
    mask = path_series.str.contains(pattern, na=False, regex=True)
    sdf = df[mask]
    if sdf.empty:
        return []
    rows = []
    grp = sdf.groupby(["client_ip", "win"])
    for (ip, win), g in grp:
        hits = len(g)
        if hits < min_hits:
            continue
        # evidence
        top_paths = g["path"].value_counts().head(15).to_dict()
        status_counts = g["status"].value_counts().to_dict()
        # confidence: if they hit many distinct sensitive targets, it's very strong
        distinct_targets = g["path"].nunique()
        confidence = 0.8
        if distinct_targets >= 10:
            confidence = 0.95
        elif distinct_targets >= 5:
            confidence = 0.9
        confidence = round(confidence, 2)
        rows.append({
            "incident_type": "Sensitive File / Exploit Probe",
            "timestamp_start": win.isoformat(),
            "timestamp_end": (win + pd.Timedelta(minutes=window_minutes)).isoformat(),
            "source_ips": [ip],
            "evidence": {
                "hits": hits,
                "distinct_targets": int(distinct_targets),
                "top_paths": top_paths,
                "status_counts": status_counts,
                "top_user_agents": g["user_agent"].value_counts().head(5).to_dict() if "user_agent" in g else {},
            },
            "severity": "High",
            "confidence": confidence,
            "recommended_actions": [
                "Block IP immediately (this is high-risk probing).",
                "Enable/verify WAF managed rules and rate limiting.",
                "Search server/app for exposure of targeted files (.env, .git, phpinfo, phpunit).",
                "Confirm no suspicious 200/302 responses on sensitive targets; investigate if present.",
            ],
        })
    return rows


def merge_cases(cases, gap_minutes=0):
    """
    Merge adjacent cases with the same incident_type and same single source IP.
    gap_minutes=0 means windows must touch exactly.
    gap_minutes=1 allows a small gap between windows.
    """
    if not cases:
        return []
    # Sort by type, ip, time
    def key(c):
        ip = (c.get("source_ips") or [""])[0]
        return (c.get("incident_type", ""), ip, c.get("timestamp_start", ""))
    cases = sorted(cases, key=key)
    merged = []
    for c in cases:
        ip_list = c.get("source_ips") or []
        ip = ip_list[0] if ip_list else None
        if not merged:
            merged.append(c)
            continue
        last = merged[-1]
        last_ip_list = last.get("source_ips") or []
        last_ip = last_ip_list[0] if last_ip_list else None
        same_type = c.get("incident_type") == last.get("incident_type")
        same_ip = ip is not None and ip == last_ip
        if not (same_type and same_ip):
            merged.append(c)
            continue
        start = pd.to_datetime(c["timestamp_start"], utc=True)
        end = pd.to_datetime(c["timestamp_end"], utc=True)
        last_start = pd.to_datetime(last["timestamp_start"], utc=True)
        last_end = pd.to_datetime(last["timestamp_end"], utc=True)
        # If this window starts within allowed gap after last window, merge
        allowed_gap = pd.Timedelta(minutes=gap_minutes)
        if start <= last_end + allowed_gap:
            # Extend the time window
            last["timestamp_end"] = max(last_end, end).isoformat()
            # Merge evidence safely (keep things explainable)
            ev_last = last.get("evidence") or {}
            ev_new = c.get("evidence") or {}
            # Sum some numeric evidence keys if present
            for k in ["requests", "login_attempts", "hits"]:
                if k in ev_last and k in ev_new and isinstance(ev_last[k], (int, float)) and isinstance(ev_new[k], (int, float)):
                    ev_last[k] = ev_last[k] + ev_new[k]
            # Max (peak) metrics for scan windows
            for k in ["unique_paths_window", "unique_ratio_window", "404_ratio_window", "distinct_targets"]:
                if k in ev_last and k in ev_new and isinstance(ev_last[k], (int, float)) and isinstance(ev_new[k], (int, float)):
                    ev_last[k] = max(ev_last[k], ev_new[k])
            # Merge top_paths dicts if present (sum counts)
            if isinstance(ev_last.get("top_paths"), dict) and isinstance(ev_new.get("top_paths"), dict):
                combined = dict(ev_last["top_paths"])
                for p, cnt in ev_new["top_paths"].items():
                    combined[p] = combined.get(p, 0) + cnt
                # keep top 15
                ev_last["top_paths"] = dict(sorted(combined.items(), key=lambda x: x[1], reverse=True)[:15])
            # Merge status_counts dicts
            if isinstance(ev_last.get("status_counts"), dict) and isinstance(ev_new.get("status_counts"), dict):
                combined = dict(ev_last["status_counts"])
                for s, cnt in ev_new["status_counts"].items():
                    combined[int(s)] = combined.get(int(s), 0) + cnt
                ev_last["status_counts"] = dict(sorted(combined.items(), key=lambda x: x[0]))
            last["evidence"] = ev_last
            # Confidence/severity: keep the max (more conservative)
            if "confidence" in c and c["confidence"] is not None:
                last["confidence"] = max(last.get("confidence") or 0, c["confidence"])
            if (last.get("severity") == "Medium" and c.get("severity") == "High") or (last.get("severity") == "Low" and c.get("severity") in ["Medium", "High"]):
                last["severity"] = c.get("severity")
        else:
            merged.append(c)
    return merged

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
    cases.extend(detect_web_scans(df, window_minutes, scan_unique_paths_threshold, scan_404_ratio_threshold))
    cases.extend(detect_sensitive_file_probes(df, window_minutes, min_hits=5))
    cases.extend(detect_bruteforce(df, window_minutes, brute_force_threshold))
    cases.extend(detect_dos_bursts(df, window_minutes, dos_rpm_threshold))
    
    cases = merge_cases(cases, gap_minutes=0)
    cases.sort(key=lambda c: c.get("timestamp_start", ""))
    return cases