#!/bin/bash
set -e

VENV=".venv"
PYTHON="$VENV/bin/python"

# Создаём venv если нет
if [ ! -f "$PYTHON" ]; then
    echo ">>> Создаю виртуальное окружение..."
    python3 -m venv "$VENV"
    "$PYTHON" -m pip install -q -r requirements.txt
    echo ">>> Зависимости установлены"
fi

case "${1:-help}" in
    generate)
        echo ">>> Генерация тестового лога..."
        "$PYTHON" generate_logs.py --output test_access.log --duration 10 --attack-rps 200
        ;;
    analyze)
        echo ">>> Анализ лога..."
        "$PYTHON" main.py file test_access.log --method both --dry-run
        ;;
    test)
        echo ">>> Запуск тестов..."
        "$PYTHON" -m pytest tests/test_system.py -v
        ;;
    all)
        bash "$0" generate
        bash "$0" analyze
        bash "$0" test
        ;;
    live)
        # Реальный режим: два терминала
        # Терминал 1: ./run.sh live        — пишет трафик в live.log
        # Терминал 2: ./run.sh watch       — мониторит live.log
        echo ">>> Симуляция живого трафика → live.log (атака через 20с)"
        "$PYTHON" simulate_live.py --log live.log --attack-after 20 --attack-rps 50
        ;;
    watch)
        LOG="${2:-live.log}"
        echo ">>> Мониторинг $LOG (интервал 5с, Ctrl+C для остановки)"
        "$PYTHON" main.py watch "$LOG" --method statistical --dry-run --interval 5
        ;;
    *)
        echo "Использование: ./run.sh [команда]"
        echo ""
        echo "  generate  — сгенерировать test_access.log"
        echo "  analyze   — анализ готового лога"
        echo "  test      — запустить все тесты"
        echo "  all       — generate + analyze + test"
        echo ""
        echo "  Реальный режим (два терминала):"
        echo "    Терминал 1:  ./run.sh live     # пишет трафик, атака через 20с"
        echo "    Терминал 2:  ./run.sh watch    # детектирует и блокирует"
        ;;
esac
