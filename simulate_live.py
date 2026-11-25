"""
Симулятор живого трафика: дописывает строки в лог-файл в реальном времени.
Через N секунд вшивает DDoS-атаку.
"""
import time
import random
import argparse
from datetime import datetime

NORMAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 4) for j in range(1, 10)]
ATTACK_IPS = ["192.168.100.1", "192.168.100.2"]
PATHS = ["/", "/api/data", "/login", "/static/app.js"]
UA_NORMAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
UA_ATTACK = "DDoS-Bot/1.0"


def make_line(ip, status=200, ua=UA_NORMAL):
    ts = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0300")
    path = random.choice(PATHS)
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {random.randint(200,2000)} "-" "{ua}"\n'


def simulate(log_path: str, attack_after: int = 20, attack_rps: int = 50):
    print(f"Запись трафика в {log_path}")
    print(f"Атака начнётся через {attack_after}с (Ctrl+C для остановки)")

    start = time.time()
    with open(log_path, "a") as f:
        while True:
            elapsed = time.time() - start
            attacking = elapsed >= attack_after

            # Нормальный трафик: ~5 req/s
            for _ in range(random.randint(3, 7)):
                f.write(make_line(random.choice(NORMAL_IPS)))

            # Атака
            if attacking:
                for _ in range(attack_rps):
                    f.write(make_line(random.choice(ATTACK_IPS), ua=UA_ATTACK))
                f.flush()
                print(f"\r[{elapsed:.0f}s] АТАКА АКТИВНА — {attack_rps} req/s от {ATTACK_IPS}", end="")
            else:
                f.flush()
                print(f"\r[{elapsed:.0f}s] Нормальный трафик, атака через {attack_after - elapsed:.0f}с", end="")

            time.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="live.log")
    parser.add_argument("--attack-after", type=int, default=20)
    parser.add_argument("--attack-rps", type=int, default=50)
    args = parser.parse_args()
    simulate(args.log, args.attack_after, args.attack_rps)
