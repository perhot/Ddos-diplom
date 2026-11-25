"""
Генератор тестовых access.log в формате nginx/apache.
Вшивает DDoS-атаки от заданных IP в указанные временные окна.
"""
import random
import argparse
from datetime import datetime, timedelta

NORMAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 20)]
ATTACK_IPS = ["192.168.100.1", "192.168.100.2", "172.16.50.10"]

PATHS = ["/", "/index.html", "/api/data", "/login", "/static/app.js"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Go-http-client/1.1",
]
ATTACK_UA = "DDoS-Bot/1.0"


def fmt_time(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0300")


def make_line(ip: str, dt: datetime, status: int = 200, ua: str = None) -> str:
    path = random.choice(PATHS)
    ua = ua or random.choice(USER_AGENTS)
    size = random.randint(200, 5000)
    return f'{ip} - - [{fmt_time(dt)}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def generate(output: str, duration_min: int = 10, attack_rps: int = 200):
    start = datetime(2024, 1, 15, 12, 0, 0)
    end = start + timedelta(minutes=duration_min)

    # Атака: с 3-й по 7-ю минуту
    attack_start = start + timedelta(minutes=3)
    attack_end = start + timedelta(minutes=7)

    lines = []
    current = start
    while current < end:
        # Нормальный трафик: ~5 req/s суммарно
        for _ in range(random.randint(3, 7)):
            ip = random.choice(NORMAL_IPS)
            lines.append((current, make_line(ip, current)))

        # Атака
        if attack_start <= current < attack_end:
            for _ in range(attack_rps):
                ip = random.choice(ATTACK_IPS)
                lines.append((current, make_line(ip, current, status=200, ua=ATTACK_UA)))

        current += timedelta(seconds=1)

    lines.sort(key=lambda x: x[0])
    with open(output, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    print(f"Сгенерировано {len(lines)} строк → {output}")
    print(f"Атакующие IP: {ATTACK_IPS}")
    print(f"Период атаки: {attack_start} – {attack_end}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="test_access.log")
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--attack-rps", type=int, default=200)
    args = parser.parse_args()
    generate(args.output, args.duration, args.attack_rps)
