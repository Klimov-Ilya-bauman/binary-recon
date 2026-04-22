.PHONY: help build install clean test lint run-tui run-cli

PREFIX ?= /usr/local
PYTHON ?= python3

help:
	@echo "Binary Recon - Makefile targets:"
	@echo ""
	@echo "  make build       — Собрать C++ ядро"
	@echo "  make install     — Установить в систему (может потребовать sudo)"
	@echo "  make clean       — Удалить артефакты сборки"
	@echo "  make test        — Запустить все тесты"
	@echo "  make lint        — Запустить линтеры"
	@echo "  make run-tui     — Запустить TUI из исходников"
	@echo "  make run-cli ARGS='/bin/ls' — Запустить CLI с аргументами"
	@echo ""

build:
	@echo "=== Сборка C++ ядра ==="
	cd core/build && cmake .. && $(MAKE)
	@echo "=== Сборка Python пакета ==="
	cd python && $(PYTHON) -m pip install -e . --break-system-packages

install: build
	@echo "=== Установка в $(PREFIX) ==="
	install -d $(PREFIX)/lib/binary-recon
	install -m 755 core/build/core $(PREFIX)/lib/binary-recon/core
	cd python && $(PYTHON) -m pip install . --break-system-packages

clean:
	rm -rf core/build/*
	rm -rf python/build python/dist python/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

test:
	@echo "=== C++ tests ==="
	@if [ -d tests/core ] && [ -n "$$(ls tests/core/*.sh 2>/dev/null)" ]; then \
		for t in tests/core/*.sh; do bash "$$t" || exit 1; done; \
	else \
		echo "No C++ tests yet"; \
	fi
	@echo "=== Python tests ==="
	@if [ -d tests/python ] && [ -n "$$(ls tests/python/test_*.py 2>/dev/null)" ]; then \
		cd python && $(PYTHON) -m pytest ../tests/python -v; \
	else \
		echo "No Python tests yet"; \
	fi

lint:
	cd python && $(PYTHON) -m ruff check recon/

run-tui:
	cd python && $(PYTHON) -m recon.tui.app

run-cli:
	cd python && $(PYTHON) -m recon $(ARGS)
