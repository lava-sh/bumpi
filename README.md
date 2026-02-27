# bumpi

`bumpi` обновляет версии Python-зависимостей в `pyproject.toml` по правилам:
- только выбранные секции/пакеты;
- только выбранные операторы версии (по умолчанию только `==`);
- запускает `uv lock --upgrade` только если были реальные обновления и есть поддерживаемый lock-файл.

## Что обновляется

Поддерживаемые зоны:
- `[project].dependencies`
- `[dependency-groups].<group>`
- `[build-system].requires`

Поддерживаемые операторы:
- `==`, `!=`, `>=`, `<=`, `>`, `<`, `~=`, `===`

По умолчанию обновляются только зависимости с оператором `==`.

## GitHub Action

```yaml
name: bump deps

on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * 1"

jobs:
  bump:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: YOUR_ORG/bumpi@v1
        with:
          python-version: "3.13"
          update-targets: '["dependencies","dependency-groups","build-system.requires"]'
          update-operators: '["=="]'
```

## Inputs Action

- `python-version`:
  - версия Python для запуска `bumpi`
  - default: `"3.14"`

- `update-targets`:
  - JSON `list[str]` со списком целей
  - default: `["dependencies","dependency-groups","build-system.requires"]`

- `update-operators`:
  - JSON `list[str]` с операторами, которые можно обновлять
  - default: `["=="]`

## Форматы `update-targets`

Общие:
- `dependencies`
- `dependency-groups`
- `build-system.requires`

Точечные:
- `dependencies:packaging`
- `dependencies.packaging`
- `dependency-groups.ci`
- `dependency-groups.ci:ruff`

Примеры:
- обновлять только `packaging` из `[project].dependencies`:
  - `["dependencies:packaging"]`
- обновлять только `ruff` в группе `ci`:
  - `["dependency-groups.ci:ruff"]`
- обновлять всю группу `ci`:
  - `["dependency-groups.ci"]`

## Конфликты (ошибка)

`bumpi` завершится с ошибкой, если указаны конфликтующие цели:
- `dependencies` вместе с `dependencies:<package>`/`dependencies.<package>`
- `dependency-groups` вместе с `dependency-groups.<group>` или `dependency-groups.<group>:<package>`
- `dependency-groups.<group>` вместе с `dependency-groups.<group>:<package>` для одной и той же группы

## Warning для include-group

Если выбрана цель вида `dependency-groups.dev`, но у `dev` нет прямых строк зависимостей (например только `{ include-group = "ci" }`), будет warning:
- `Warning: dependency-groups.dev has no direct dependencies to update ...`

## Поведение lock-файла

После обновления `pyproject.toml` выполняется `uv lock --upgrade` только когда одновременно:
- есть реальные изменения версий;
- в корне найден поддерживаемый lock-файл (сейчас: `uv.lock`).

Если обновлений нет, lock-команда не запускается.

## Локальный запуск

Через script entry point:

```bash
bumpi
```

С env-переменными:

```bash
export BUMPI_UPDATE_TARGETS='["dependencies:packaging","dependency-groups.ci:ruff"]'
export BUMPI_UPDATE_OPERATORS='["==",">="]'
bumpi
```

PowerShell:

```powershell
$env:BUMPI_UPDATE_TARGETS='["dependencies:packaging"]'
$env:BUMPI_UPDATE_OPERATORS='["=="]'
bumpi
```
