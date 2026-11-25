"""
Тесты для всех модулей системы.
"""
import os
import tempfile
import pytest
from datetime import datetime, timezone, timedelta

from log_analyzer import parse_line, parse_file, compute_metrics, LogEntry
from detector import detect_statistical, detect_isolation_forest, Verdict, init_db, save_events, DetectionEvent
from responder import block_ip, unblock_ip, respond, WHITELIST, _blocked

TZ = timezone(timedelta(hours=3))


# ── Фикстуры ──────────────────────────────────────────────────────────────────

def make_entry(ip: str, seconds_offset: int = 0, status: int = 200, ua: str = "Mozilla/5.0") -> LogEntry:
    t = datetime(2024, 1, 15, 12, 0, seconds_offset, tzinfo=TZ)
    return LogEntry(ip=ip, time=t, method="GET", path="/", status=status, size=500, ua=ua)


def make_log_line(ip: str, dt: datetime, status: int = 200) -> str:
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0300")
    return f'{ip} - - [{ts}] "GET / HTTP/1.1" {status} 512 "-" "Mozilla/5.0"'


# ── log_analyzer ──────────────────────────────────────────────────────────────

class TestParseLine:
    def test_valid_line(self):
        line = '1.2.3.4 - - [15/Jan/2024:12:00:00 +0300] "GET /index HTTP/1.1" 200 1024 "-" "curl/7.68"'
        e = parse_line(line)
        assert e is not None
        assert e.ip == "1.2.3.4"
        assert e.status == 200
        assert e.path == "/index"
        assert e.ua == "curl/7.68"

    def test_invalid_line(self):
        assert parse_line("garbage line") is None

    def test_status_parsed(self):
        line = '5.5.5.5 - - [15/Jan/2024:12:00:00 +0300] "POST /login HTTP/1.1" 403 200 "-" "bot"'
        e = parse_line(line)
        assert e.status == 403


class TestComputeMetrics:
    def test_rps_calculation(self):
        # 100 запросов за 10 секунд → rps ≈ 10
        entries = [make_entry("1.1.1.1", i) for i in range(10)] * 10
        metrics = compute_metrics(entries)
        assert "1.1.1.1" in metrics
        assert metrics["1.1.1.1"].rps > 5

    def test_error_ratio(self):
        entries = [make_entry("2.2.2.2", i, status=200) for i in range(6)]
        entries += [make_entry("2.2.2.2", i + 10, status=404) for i in range(4)]
        metrics = compute_metrics(entries)
        assert abs(metrics["2.2.2.2"].error_ratio - 0.4) < 0.01

    def test_multiple_ips(self):
        entries = [make_entry("1.1.1.1", i) for i in range(5)]
        entries += [make_entry("2.2.2.2", i) for i in range(3)]
        metrics = compute_metrics(entries)
        assert len(metrics) == 2

    def test_empty_entries(self):
        assert compute_metrics([]) == {}

    def test_parse_file(self, tmp_path):
        log = tmp_path / "test.log"
        dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=TZ)
        lines = [make_log_line("3.3.3.3", dt + timedelta(seconds=i)) for i in range(5)]
        log.write_text("\n".join(lines) + "\n")
        entries = parse_file(str(log))
        assert len(entries) == 5
        assert all(e.ip == "3.3.3.3" for e in entries)


# ── detector ──────────────────────────────────────────────────────────────────

def make_metrics_dict(ip_rps: dict):
    """Создаёт словарь метрик из {ip: rps}."""
    from log_analyzer import IPMetrics
    return {
        ip: IPMetrics(ip=ip, request_count=int(rps * 60), rps=rps,
                      error_ratio=0.01, unique_paths=3, unique_uas=1, window_seconds=60)
        for ip, rps in ip_rps.items()
    }


class TestStatisticalDetector:
    def test_detects_attack(self):
        # Один IP с аномально высоким RPS
        metrics = make_metrics_dict({
            "1.1.1.1": 2.0, "1.1.1.2": 2.5, "1.1.1.3": 1.8,
            "1.1.1.4": 2.1, "attacker": 500.0,
        })
        events = detect_statistical(metrics)
        attacker_event = next(e for e in events if e.ip == "attacker")
        assert attacker_event.verdict == Verdict.ATTACK

    def test_normal_traffic_not_flagged(self):
        metrics = make_metrics_dict({"a": 2.0, "b": 2.1, "c": 1.9, "d": 2.05})
        events = detect_statistical(metrics)
        assert all(e.verdict == Verdict.NORMAL for e in events)

    def test_too_few_ips(self):
        metrics = make_metrics_dict({"only_one": 100.0})
        events = detect_statistical(metrics)
        assert events == []

    def test_z_score_in_event(self):
        # Нормальный трафик с небольшим разбросом → MAD > 0 → высокий z для атакующего
        metrics = make_metrics_dict({
            "n1": 1.0, "n2": 1.5, "n3": 2.0, "n4": 1.2, "n5": 1.8, "attacker": 200.0
        })
        events = detect_statistical(metrics)
        attacker_event = next(e for e in events if e.ip == "attacker")
        assert attacker_event.verdict == Verdict.ATTACK
        assert attacker_event.score > 3.0


class TestIsolationForest:
    def test_detects_anomaly(self):
        # Нужно минимум 4 IP для IF
        metrics = make_metrics_dict({
            "n1": 2.0, "n2": 2.1, "n3": 1.9, "n4": 2.05,
            "n5": 2.2, "n6": 1.8, "n7": 2.3, "n8": 1.95,
            "attacker": 800.0,
        })
        events = detect_isolation_forest(metrics, contamination=0.1)
        attacker_event = next(e for e in events if e.ip == "attacker")
        assert attacker_event.verdict in (Verdict.ATTACK, Verdict.SUSPICIOUS)

    def test_too_few_ips(self):
        metrics = make_metrics_dict({"a": 1.0, "b": 2.0})
        assert detect_isolation_forest(metrics) == []


class TestDatabase:
    def test_save_and_load(self, tmp_path):
        db = str(tmp_path / "test.db")
        events = [
            DetectionEvent("1.1.1.1", Verdict.ATTACK, 500.0, 30000, 4.5, "statistical"),
            DetectionEvent("2.2.2.2", Verdict.NORMAL, 2.0, 120, 0.1, "statistical"),
        ]
        save_events(events, db_path=db)
        import sqlite3
        conn = sqlite3.connect(db)
        rows = conn.execute("SELECT ip, verdict FROM events").fetchall()
        conn.close()
        assert len(rows) == 2
        assert ("1.1.1.1", "attack") in rows
        assert ("2.2.2.2", "normal") in rows


# ── responder ─────────────────────────────────────────────────────────────────

class TestResponder:
    def setup_method(self):
        _blocked.clear()

    def test_whitelist_not_blocked(self):
        ok = block_ip("127.0.0.1", dry_run=True)
        assert ok is False

    def test_dry_run_block(self):
        ok = block_ip("9.9.9.9", dry_run=True)
        assert ok is True
        assert "9.9.9.9" in _blocked
        _blocked["9.9.9.9"].cancel()

    def test_double_block_skipped(self):
        block_ip("8.8.8.8", dry_run=True)
        ok2 = block_ip("8.8.8.8", dry_run=True)
        assert ok2 is False
        _blocked["8.8.8.8"].cancel()

    def test_unblock(self):
        block_ip("7.7.7.7", dry_run=True)
        ok = unblock_ip("7.7.7.7", dry_run=True)
        assert ok is True
        assert "7.7.7.7" not in _blocked

    def test_respond_blocks_attacks(self):
        events = [
            DetectionEvent("10.0.0.1", Verdict.ATTACK, 500.0, 30000, 4.5, "statistical"),
            DetectionEvent("10.0.0.2", Verdict.NORMAL, 2.0, 120, 0.1, "statistical"),
        ]
        respond(events, dry_run=True)
        assert "10.0.0.1" in _blocked
        assert "10.0.0.2" not in _blocked
        _blocked["10.0.0.1"].cancel()

    def test_respond_suspicious_not_blocked(self):
        events = [DetectionEvent("11.0.0.1", Verdict.SUSPICIOUS, 50.0, 3000, 2.1, "statistical")]
        respond(events, dry_run=True)
        assert "11.0.0.1" not in _blocked


# ── Интеграционный тест ───────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline(self, tmp_path):
        """Генерируем лог с атакой → парсим → детектируем → реагируем."""
        _blocked.clear()
        log = tmp_path / "access.log"
        dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=TZ)

        lines = []
        # Нормальный трафик: 10 IP × 1 req/s × 90s = 900 строк
        for i in range(10):
            ip = f"10.0.0.{i+1}"
            for s in range(90):
                lines.append(make_log_line(ip, dt + timedelta(seconds=s)))

        # Атакующий: ~1 req/s × 90s + burst = 100 строк (итого ~1000)
        for s in range(90):
            lines.append(make_log_line("192.168.100.1", dt + timedelta(seconds=s)))
        # burst: ещё 10 запросов в секунду 0 → rps атакующего >> нормальных
        for _ in range(10):
            lines.append(make_log_line("192.168.100.1", dt))

        log.write_text("\n".join(lines) + "\n")

        entries = parse_file(str(log))
        metrics = compute_metrics(entries)
        events = detect_statistical(metrics)
        respond(events, dry_run=True)

        assert "192.168.100.1" in _blocked
        # Нормальные IP не заблокированы
        for i in range(10):
            assert f"10.0.0.{i+1}" not in _blocked

        # Очистка таймеров
        for t in list(_blocked.values()):
            t.cancel()
        _blocked.clear()
