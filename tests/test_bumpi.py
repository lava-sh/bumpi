import textwrap
from pathlib import Path
from uuid import uuid4

import pytest

import bumpi.main as bumpi_main
from bumpi.main import (
    DEFAULT_OPERATORS,
    TargetSelection,
    parse_operators_env,
    parse_targets_env,
)


def create_case_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    root = (Path.cwd() / ".tmp_test" / uuid4().hex).resolve()
    root.mkdir(parents=True, exist_ok=False)
    monkeypatch.chdir(root)
    return root


def test_parse_targets_env_default() -> None:
    selection = parse_targets_env("")
    assert selection == TargetSelection(
        update_dependencies=True,
        update_dependency_groups=True,
        update_build_system_requires=True,
    )


def test_parse_targets_env_dependencies_package() -> None:
    selection = parse_targets_env("dependencies:packaging")
    assert selection.dependency_packages == {"packaging"}
    assert not selection.update_dependencies


def test_parse_targets_env_group_package() -> None:
    selection = parse_targets_env("dependency-groups.ci:ruff")
    assert selection.dependency_group_packages == {"ci": {"ruff"}}
    assert selection.explicit_groups == {"ci"}


def test_parse_targets_env_rejects_dependencies_conflict() -> None:
    with pytest.raises(SystemExit):
        parse_targets_env("dependencies, dependencies.packaging")


def test_parse_targets_env_csv_ignores_spaces() -> None:
    selection = parse_targets_env("dependencies, dependency-groups.ci:ruff")
    assert selection.update_dependencies
    assert selection.dependency_group_packages == {"ci": {"ruff"}}


def test_parse_operators_env_empty_uses_defaults() -> None:
    operators = parse_operators_env("")
    assert operators == DEFAULT_OPERATORS


def test_parse_operators_env_csv_ignores_spaces() -> None:
    operators = parse_operators_env("==, >=")
    assert operators == {"==", ">="}


def test_parse_operators_env_rejects_unknown_operator() -> None:
    with pytest.raises(SystemExit):
        parse_operators_env("==, =>")


def test_main_updates_only_selected_dependency_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_case_workspace(monkeypatch)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        textwrap.dedent(
            """
            [project]
            dependencies = ["packaging == 1.0.0", "pyreqwest == 1.0.0"]
            """,
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("BUMPI_UPDATE_TARGETS", "dependencies:packaging")
    monkeypatch.setattr(
        bumpi_main,
        "fetch_latest_version",
        lambda package, _: {"packaging": "2.0.0", "pyreqwest": "2.0.0"}.get(package),
    )
    monkeypatch.setattr(bumpi_main, "run_lock_upgrade", lambda _: None)

    bumpi_main.main()

    updated = pyproject.read_text(encoding="utf-8")
    assert '"packaging == 2.0.0"' in updated
    assert '"pyreqwest == 1.0.0"' in updated


def test_main_updates_only_selected_group_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_case_workspace(monkeypatch)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        textwrap.dedent(
            """
            [dependency-groups]
            ci = ["ruff == 1.0.0", "pytest == 1.0.0"]
            dev = ["mypy == 1.0.0"]
            """,
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("BUMPI_UPDATE_TARGETS", "dependency-groups.ci:ruff")
    monkeypatch.setattr(
        bumpi_main,
        "fetch_latest_version",
        lambda package, _: {"ruff": "2.0.0", "pytest": "2.0.0", "mypy": "2.0.0"}.get(
            package,
        ),
    )
    monkeypatch.setattr(bumpi_main, "run_lock_upgrade", lambda _: None)

    bumpi_main.main()

    updated = pyproject.read_text(encoding="utf-8")
    assert '"ruff == 2.0.0"' in updated
    assert '"pytest == 1.0.0"' in updated
    assert '"mypy == 1.0.0"' in updated


def test_main_warns_for_group_without_direct_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = create_case_workspace(monkeypatch)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        textwrap.dedent(
            """
            [dependency-groups]
            ci = ["ruff == 1.0.0"]
            dev = [
                { include-group = "ci" },
            ]
            """,
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("BUMPI_UPDATE_TARGETS", "dependency-groups.dev")
    monkeypatch.setattr(
        bumpi_main,
        "fetch_latest_version",
        lambda package, _: {"ruff": "2.0.0"}.get(package),
    )
    monkeypatch.setattr(
        bumpi_main,
        "run_lock_upgrade",
        lambda _: (_ for _ in ()).throw(AssertionError("lock must not run")),
    )

    bumpi_main.main()
    output = capsys.readouterr().out
    assert "Warning:" in output
    assert "dependency-groups.dev" in output


def test_main_default_operator_updates_only_eq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_case_workspace(monkeypatch)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        textwrap.dedent(
            """
            [project]
            dependencies = ["alpha == 1.0.0", "beta >= 1.0.0"]
            """,
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("BUMPI_UPDATE_TARGETS", "dependencies")
    monkeypatch.setattr(
        bumpi_main,
        "fetch_latest_version",
        lambda package, _: {"alpha": "2.0.0", "beta": "2.0.0"}.get(package),
    )
    monkeypatch.setattr(bumpi_main, "run_lock_upgrade", lambda _: None)

    bumpi_main.main()

    updated = pyproject.read_text(encoding="utf-8")
    assert '"alpha == 2.0.0"' in updated
    assert '"beta >= 1.0.0"' in updated


def test_main_runs_lock_upgrade_when_supported_lock_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_case_workspace(monkeypatch)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        textwrap.dedent(
            """
            [project]
            dependencies = ["alpha == 1.0.0"]
            """,
        ),
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("", encoding="utf-8")

    calls: list[Path] = []

    monkeypatch.setenv("BUMPI_UPDATE_TARGETS", "dependencies")
    monkeypatch.setattr(
        bumpi_main,
        "fetch_latest_version",
        lambda package, _: {"alpha": "2.0.0"}.get(package),
    )
    monkeypatch.setattr(bumpi_main, "run_lock_upgrade", lambda path: calls.append(path))

    bumpi_main.main()

    assert calls == [root]


def test_main_skips_lock_upgrade_without_supported_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = create_case_workspace(monkeypatch)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        textwrap.dedent(
            """
            [project]
            dependencies = ["alpha == 1.0.0"]
            """,
        ),
        encoding="utf-8",
    )

    called = False

    def mark_called(_: Path) -> None:
        nonlocal called
        called = True

    monkeypatch.setenv("BUMPI_UPDATE_TARGETS", "dependencies")
    monkeypatch.setattr(
        bumpi_main,
        "fetch_latest_version",
        lambda package, _: {"alpha": "2.0.0"}.get(package),
    )
    monkeypatch.setattr(bumpi_main, "run_lock_upgrade", mark_called)

    bumpi_main.main()

    assert called is False
