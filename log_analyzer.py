"""
Парсер и анализатор nginx/apache access.log.
Возвращает метрики по каждому IP за скользящее временное окно.
"""
import re
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\d+) "[^"]*" "(?P<ua>[^"]*)"'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogEntry:
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    size: int
    ua: str


@dataclass
class IPMetrics:
    ip: str
    request_count: int = 0
    rps: float = 0.0
    error_ratio: float = 0.0       # доля 4xx/5xx
    unique_paths: int = 0
    unique_uas: int = 0
    window_seconds: int = 0


def parse_line(line: str) -> LogEntry | None:
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    return LogEntry(
        ip=m.group("ip"),
        time=datetime.strptime(m.group("time"), TIME_FMT),
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        size=int(m.group("size")),
        ua=m.group("ua"),
    )


def parse_file(path: str) -> List[LogEntry]:
    entries = []
    with open(path) as f:
        for line in f:
            e = parse_line(line)
            if e:
                entries.append(e)
    return entries


def compute_metrics(entries: List[LogEntry], window_sec: int = 60) -> Dict[str, IPMetrics]:
    """Считает метрики по IP за скользящее окно window_sec секунд."""
    if not entries:
        return {}

    # Группируем по IP
    by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in entries:
        by_ip[e.ip].append(e)

    metrics = {}
    for ip, elist in by_ip.items():
        elist.sort(key=lambda x: x.time)
        t_start = elist[0].time
        t_end = elist[-1].time
        span = max((t_end - t_start).total_seconds(), 1)

        errors = sum(1 for e in elist if e.status >= 400)
        m = IPMetrics(
            ip=ip,
            request_count=len(elist),
            rps=len(elist) / span,
            error_ratio=errors / len(elist),
            unique_paths=len({e.path for e in elist}),
            unique_uas=len({e.ua for e in elist}),
            window_seconds=int(span),
        )
        metrics[ip] = m

    return metrics
