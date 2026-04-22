# Binary Recon

> Static analysis tool for ELF and PE executables with interactive terminal interface

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-green.svg)

Binary Recon анализирует исполняемые файлы без их запуска: парсит структуру (секции, импорты, строки), вычисляет энтропию и криптографические хеши, прогоняет через 7 детекторов подозрительного поведения и выдаёт итоговый Risk Score 0-100.

## Возможности

- Парсинг ELF (Linux) и PE (Windows) исполняемых файлов
- Вычисление MD5 и SHA256 хешей (собственная реализация по RFC)
- Расчёт энтропии Шеннона для файла и отдельных секций
- 7 детекторов: AntiDebug, Network, Packer, Persistence, Injection, Crypto, Signatures
- Risk Score 0-100 с уровнями CLEAN / LOW / MEDIUM / HIGH / CRITICAL
- Интерактивный TUI на Textual
- CLI режим для автоматизации
- История сканирований в SQLite
- Экспорт в JSON, HTML, Markdown
- Batch-сканирование директорий

## Быстрый старт

### Из исходников

```bash
git clone https://github.com/YOUR-USERNAME/binary-recon.git
cd binary-recon
make build
make install
recon-tui
```

### Из релиза

Скачай подходящий под твою архитектуру архив с [Releases](https://github.com/YOUR-USERNAME/binary-recon/releases), распакуй и запусти `./install.sh`.

## Системные требования

- Linux (Ubuntu 22.04+, Debian 12+, Fedora 38+ или аналог)
- GCC 9+ или Clang 10+ с поддержкой C++17
- CMake 3.16+
- Python 3.9+
- Терминал с поддержкой 256 цветов и Unicode

## Архитектура

Двухслойная: низкоуровневый C++ движок парсит бинарники и возвращает JSON, Python-слой реализует логику детекторов, TUI и хранение. Связь через subprocess + JSON-контракт.

Подробнее — в [docs/architecture.md](docs/architecture.md) и UML-диаграммах в [docs/uml/](docs/uml/).

## Документация

- [Техническое задание (ГОСТ 19.201-78)](docs/TZ_GOST.docx)
- [User Stories, UML, MoSCoW](docs/UserStories_UML_MoSCoW.docx)
- [Документация C++ ядра](docs/CPP_Core_Documentation.docx)

## Лицензия

MIT — см. [LICENSE](LICENSE).
