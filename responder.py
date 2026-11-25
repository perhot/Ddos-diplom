"""
Модуль автоматического реагирования.
Блокирует IP через iptables (требует root).
В тестовом режиме (dry_run=True) только логирует действия.
"""
import subprocess
import logging
import time
from threading import Timer
from typing import Set

from detector import DetectionEvent, Verdict

logger = logging.getLogger(__name__)

WHITELIST: Set[str] = {"127.0.0.1", "::1"}
_blocked: dict[str, Timer] = {}   # ip → таймер авторазблокировки


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("iptables error: %s", e.stderr.decode())
        return False


def block_ip(ip: str, duration_sec: int = 300, dry_run: bool = True) -> bool:
    if ip in WHITELIST:
        logger.info("SKIP whitelist: %s", ip)
        return False
    if ip in _blocked:
        logger.info("Already blocked: %s", ip)
        return False

    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    if dry_run:
        logger.info("[DRY-RUN] Would block %s for %ds: %s", ip, duration_sec, " ".join(cmd))
        ok = True
    else:
        ok = _run(cmd)

    if ok:
        logger.warning("BLOCKED %s for %ds", ip, duration_sec)
        t = Timer(duration_sec, unblock_ip, args=[ip, dry_run])
        t.daemon = True
        t.start()
        _blocked[ip] = t
    return ok


def unblock_ip(ip: str, dry_run: bool = True) -> bool:
    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    if dry_run:
        logger.info("[DRY-RUN] Would unblock %s: %s", ip, " ".join(cmd))
        ok = True
    else:
        ok = _run(cmd)

    if ok:
        logger.info("UNBLOCKED %s", ip)
        _blocked.pop(ip, None)
    return ok


def respond(events: list[DetectionEvent], dry_run: bool = True, block_duration: int = 300):
    """Обрабатывает список событий: блокирует ATTACK, логирует SUSPICIOUS."""
    for e in events:
        if e.verdict == Verdict.ATTACK:
            block_ip(e.ip, duration_sec=block_duration, dry_run=dry_run)
        elif e.verdict == Verdict.SUSPICIOUS:
            logger.warning("SUSPICIOUS %s rps=%.1f score=%.3f", e.ip, e.rps, e.score)
