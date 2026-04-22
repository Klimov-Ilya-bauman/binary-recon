# Архитектура Binary Recon

## Обзор

Binary Recon построен по двухслойной архитектуре:

- **C++ ядро** — низкоуровневый парсинг бинарных файлов, вычисление хешей и энтропии.
- **Python слой** — логика детекторов, Risk Score, TUI, хранение, экспорт.

## Поток данных
Пользователь
↓
TUI / CLI (Python)
↓
Analyzer (Python)
↓
CoreWrapper (subprocess)
↓
core binary (C++)    ← парсит файл
↓ JSON
CoreWrapper
↓ AnalysisResult
7 детекторов (Python)
↓ Findings
RiskCalculator
↓ RiskAssessment
Database (SQLite)   + Exporter (JSON/HTML/MD)

## JSON-контракт между слоями

Версия: `1.0`

См. [docs/json_contract.md](json_contract.md) (TBD).

## UML-диаграммы

Все диаграммы в формате PlantUML лежат в [docs/uml/](uml/):

- `class_diagram.puml` — диаграмма классов
- `object_diagram.puml` — диаграмма объектов
- `usecase_diagram.puml` — Use Case

Рендеринг PNG:

```bash
sudo apt install plantuml
plantuml docs/uml/*.puml
```
