"""
Точка входа. Два режима:
  file  — анализ готового лог-файла
  watch — мониторинг в реальном времени (tail -f)
"""
import argparse
import logging
import time
import os

from log_analyzer import parse_file, compute_metrics
from detector import detect_statistical, detect_isolation_forest, save_events
from responder import respond

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def analyze_file(log_path: str, method: str, dry_run: bool):
    logger.info("Анализ файла: %s", log_path)
    entries = parse_file(log_path)
    logger.info("Прочитано записей: %d", len(entries))

    metrics = compute_metrics(entries)
    logger.info("Уникальных IP: %d", len(metrics))

    if method in ("statistical", "both"):
        events = detect_statistical(metrics)
        save_events(events)
        respond(events, dry_run=dry_run)
        _print_summary(events, "Статистический")

    if method in ("isolation_forest", "both"):
        events = detect_isolation_forest(metrics)
        save_events(events)
        respond(events, dry_run=dry_run)
        _print_summary(events, "Isolation Forest")


def _print_summary(events, label: str):
    attacks = [e for e in events if e.verdict.value == "attack"]
    suspicious = [e for e in events if e.verdict.value == "suspicious"]
    print(f"\n{'─'*50}")
    print(f"[{label}] Атак: {len(attacks)}, Подозрительных: {len(suspicious)}")
    for e in attacks:
        print(f"  ATTACK  {e.ip:20s} rps={e.rps:.1f}  score={e.score}")
    for e in suspicious:
        print(f"  SUSPECT {e.ip:20s} rps={e.rps:.1f}  score={e.score}")


def watch_file(log_path: str, method: str, dry_run: bool, interval: int = 10):
    """Читает новые строки каждые interval секунд."""
    logger.info("Мониторинг %s (интервал %ds)", log_path, interval)
    pos = 0
    from log_analyzer import parse_line
    from collections import deque
    buffer = deque(maxlen=50_000)

    while True:
        with open(log_path) as f:
            f.seek(pos)
            new_lines = f.readlines()
            pos = f.tell()

        if new_lines:
            for line in new_lines:
                e = parse_line(line)
                if e:
                    buffer.append(e)

            metrics = compute_metrics(list(buffer))
            if method in ("statistical", "both"):
                events = detect_statistical(metrics)
                respond(events, dry_run=dry_run)
            if method in ("isolation_forest", "both"):
                events = detect_isolation_forest(metrics)
                respond(events, dry_run=dry_run)

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Auto-Response System")
    parser.add_argument("mode", choices=["file", "watch"])
    parser.add_argument("log", help="Путь к лог-файлу")
    parser.add_argument("--method", choices=["statistical", "isolation_forest", "both"], default="both")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Не применять iptables")
    parser.add_argument("--interval", type=int, default=10, help="Интервал watch-режима (сек)")
    args = parser.parse_args()

    if args.mode == "file":
        analyze_file(args.log, args.method, args.dry_run)
    else:
        watch_file(args.log, args.method, args.dry_run, args.interval)
