"""
Детектор DDoS-атак.
Метод 1: статистический (z-score по RPS).
Метод 2: Isolation Forest (sklearn).
Сохраняет события в SQLite.
"""
import sqlite3
from dataclasses import dataclass
from typing import Dict, List, Tuple
from enum import Enum

import numpy as np
from sklearn.ensemble import IsolationForest

from log_analyzer import IPMetrics

DB_PATH = "events.db"


class Verdict(Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    ATTACK = "attack"


@dataclass
class DetectionEvent:
    ip: str
    verdict: Verdict
    rps: float
    request_count: int
    score: float          # z-score или anomaly score
    method: str           # "statistical" | "isolation_forest"


# ── SQLite ────────────────────────────────────────────────────────────────────

def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, verdict TEXT, rps REAL,
            request_count INTEGER, score REAL, method TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def save_events(events: List[DetectionEvent], db_path: str = DB_PATH):
    conn = init_db(db_path)
    conn.executemany(
        "INSERT INTO events (ip, verdict, rps, request_count, score, method) VALUES (?,?,?,?,?,?)",
        [(e.ip, e.verdict.value, e.rps, e.request_count, e.score, e.method) for e in events],
    )
    conn.commit()
    conn.close()


# ── Статистический детектор ───────────────────────────────────────────────────

def detect_statistical(
    metrics: Dict[str, IPMetrics],
    z_suspicious: float = 2.0,
    z_attack: float = 3.0,
) -> List[DetectionEvent]:
    """Использует median + MAD (устойчивая статистика, не искажается выбросами)."""
    rps_values = np.array([m.rps for m in metrics.values()])
    if len(rps_values) < 2:
        return []
    median = np.median(rps_values)
    mad = np.median(np.abs(rps_values - median))
    # MAD → σ: умножаем на 1.4826 (нормировочный коэффициент)
    sigma = mad * 1.4826
    if sigma == 0:
        sigma = rps_values.std() or 1.0

    events = []
    for m in metrics.values():
        z = (m.rps - median) / sigma
        if z >= z_attack:
            verdict = Verdict.ATTACK
        elif z >= z_suspicious:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.NORMAL
        events.append(DetectionEvent(m.ip, verdict, m.rps, m.request_count, round(z, 3), "statistical"))
    return events


# ── Isolation Forest ──────────────────────────────────────────────────────────

def detect_isolation_forest(
    metrics: Dict[str, IPMetrics],
    contamination: float = 0.05,
) -> List[DetectionEvent]:
    ips = list(metrics.keys())
    if len(ips) < 4:
        return []

    X = np.array([
        [m.rps, m.request_count, m.error_ratio, m.unique_paths, m.unique_uas]
        for m in metrics.values()
    ])

    clf = IsolationForest(contamination=contamination, random_state=42)
    clf.fit(X)
    scores = clf.decision_function(X)   # чем ниже — тем аномальнее
    preds = clf.predict(X)              # -1 = аномалия, 1 = норма

    events = []
    for i, ip in enumerate(ips):
        m = metrics[ip]
        if preds[i] == -1:
            verdict = Verdict.ATTACK if scores[i] < -0.1 else Verdict.SUSPICIOUS
        else:
            verdict = Verdict.NORMAL
        events.append(DetectionEvent(ip, verdict, m.rps, m.request_count, round(float(scores[i]), 4), "isolation_forest"))
    return events
