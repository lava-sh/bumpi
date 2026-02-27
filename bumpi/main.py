import json
import subprocess
from dataclasses import dataclass, field
from os import getenv
from pathlib import Path
from typing import NamedTuple

import regex
from packaging.version import InvalidVersion, Version
from pyreqwest.exceptions import JSONDecodeError, RequestError
from pyreqwest.simple.sync_request import pyreqwest_get


def resolve_root() -> Path:
    github_workspace = getenv("GITHUB_WORKSPACE")
    if github_workspace:
        workspace = Path(github_workspace).resolve()
        if (workspace / "pyproject.toml").is_file():
            return workspace
    for candidate in (Path.cwd(), *Path.cwd().parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return Path.cwd()


SUPPORTED_OPERATORS = {"==", "!=", ">=", "<=", ">", "<", "~=", "==="}
DEFAULT_OPERATORS = {"=="}

SUPPORTED_LOCKS = [
    "uv.lock",
]


class Update(NamedTuple):
    package: str
    old: str
    new: str
    location: str


@dataclass
class TargetSelection:
    update_dependencies: bool = False
    dependency_packages: set[str] = field(default_factory=set)
    update_dependency_groups: bool = False
    dependency_groups: set[str] = field(default_factory=set)
    dependency_group_packages: dict[str, set[str]] = field(default_factory=dict)
    update_build_system_requires: bool = False
    explicit_groups: set[str] = field(default_factory=set)


SECTION_RE = regex.compile(r"^\s*\[([^]]+)]\s*$")
BUILD_REQUIRES_RE = regex.compile(r"^(\s*)requires(\s*=\s*)\[(.*)$")
PROJECT_DEPENDENCIES_RE = regex.compile(r"^(\s*)dependencies(\s*=\s*)\[(.*)$")
GROUP_LIST_RE = regex.compile(r"^(\s*)([A-Za-z0-9_-]+)(\s*=\s*)\[(.*)$")
QUOTED_RE = regex.compile(r"([\"'])([^\"']*)(\1)")
SPEC_RE = regex.compile(
    r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*)(===|==|!=|~=|>=|<=|>|<)(\s*)([^\s\"'#,;]+)(\s*)$",
)


def fetch_latest_version(package: str, cache: dict[str, str | None]) -> str | None:
    key = package.lower()
    if key in cache:
        return cache[key]
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        response = pyreqwest_get(url).error_for_status().send()
        data = response.json()
        version = data.get("info", {}).get("version")
    except (RequestError, JSONDecodeError, TypeError, AttributeError):
        version = None
    if isinstance(version, str):
        cache[key] = version
    else:
        cache[key] = None
    return cache[key]


def maybe_bump_dependency(
    dep: str,
    location: str,
    cache: dict[str, str | None],
    selected_operators: set[str],
    selected_targets: TargetSelection,
) -> tuple[str, Update | None]:
    match = SPEC_RE.fullmatch(dep)
    if not match:
        return dep, None
    lead, package, pre_op_ws, operator, post_op_ws, current_version, trail = (
        match.groups()
    )
    if not is_package_selected(selected_targets, location, package):
        return dep, None
    if operator not in selected_operators:
        return dep, None
    latest_version = fetch_latest_version(package, cache)
    if latest_version is None:
        return dep, None
    try:
        current = Version(current_version)
        latest = Version(latest_version)
    except InvalidVersion:
        return dep, None
    if latest <= current:
        return dep, None
    new_dep = f"{lead}{package}{pre_op_ws}{operator}{post_op_ws}{latest_version}{trail}"
    return new_dep, Update(package, current_version, latest_version, location)


def bump_line(
    line: str,
    location: str,
    cache: dict[str, str | None],
    selected_operators: set[str],
    selected_targets: TargetSelection,
) -> tuple[str, list[Update]]:
    updates: list[Update] = []
    parts: list[str] = []
    last_index = 0
    for quoted in QUOTED_RE.finditer(line):
        start, end = quoted.span()
        parts.append(line[last_index:start])
        quote = quoted.group(1)
        value = quoted.group(2)
        new_value, update = maybe_bump_dependency(
            value,
            location,
            cache,
            selected_operators,
            selected_targets,
        )
        if update is not None:
            updates.append(update)
        parts.append(f"{quote}{new_value}{quote}")
        last_index = end
    parts.append(line[last_index:])
    return "".join(parts), updates


def render_updates(updates: list[Update]) -> None:
    if not updates:
        print("No dependency updates found.")
        return
    package_width = max(len(update.package) for update in updates)
    old_width = max(len(update.old) for update in updates)
    new_width = max(len(update.new) for update in updates)
    for update in updates:
        package = f"{update.package:<{package_width}}"
        old_version = f"{update.old:>{old_width}}"
        new_version = f"{update.new:<{new_width}}"
        print(f"{package} {old_version} -> {new_version} | {update.location}")


def parse_targets_env(raw: str | None) -> TargetSelection:
    if raw is None or not raw.strip():
        return default_target_selection()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = (
            "`BUMPI_UPDATE_TARGETS` must be a JSON list[str], "
            'for example: ["dependencies","dependency-groups.ci:ruff"]'
        )
        raise SystemExit(msg) from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        msg = (
            "`BUMPI_UPDATE_TARGETS` must be a JSON list[str], "
            'for example: ["dependencies","dependency-groups.ci:ruff"]'
        )
        raise SystemExit(msg)

    selection = TargetSelection()
    for raw_item in parsed:
        parse_target_item(selection, raw_item.strip())

    validate_target_selection(selection)
    return selection


def default_target_selection() -> TargetSelection:
    return TargetSelection(
        update_dependencies=True,
        update_dependency_groups=True,
        update_build_system_requires=True,
    )


def parse_target_item(selection: TargetSelection, item: str) -> None:
    if not item:
        return
    if item == "dependencies":
        selection.update_dependencies = True
        return
    if item == "dependency-groups":
        selection.update_dependency_groups = True
        return
    if item == "build-system.requires":
        selection.update_build_system_requires = True
        return
    if item.startswith("dependencies:"):
        pkg = item.split(":", 1)[1].strip().lower()
        if not pkg:
            msg = "`dependencies:<package>` requires a package name."
            raise SystemExit(msg)
        selection.dependency_packages.add(pkg)
        return
    if item.startswith("dependencies."):
        pkg = item.split(".", 1)[1].strip().lower()
        if not pkg:
            msg = "`dependencies.<package>` requires a package name."
            raise SystemExit(msg)
        selection.dependency_packages.add(pkg)
        return
    if item.startswith("dependency-groups."):
        parse_dependency_group_selector(selection, item)
        return
    supported = (
        "dependencies, dependencies:<package>, dependencies.<package>, "
        "dependency-groups, dependency-groups.<group>, "
        "dependency-groups.<group>:<package>, build-system.requires"
    )
    msg = f"Unknown target `{item}`. Supported values: {supported}"
    raise SystemExit(msg)


def parse_dependency_group_selector(selection: TargetSelection, item: str) -> None:
    rest = item.split(".", 1)[1].strip()
    if not rest:
        msg = "`dependency-groups.<group>` requires a group name."
        raise SystemExit(msg)
    if ":" in rest:
        group, pkg = rest.split(":", 1)
        group = group.strip()
        pkg = pkg.strip().lower()
        if not group or not pkg:
            msg = (
                "`dependency-groups.<group>:<package>` requires both "
                "group and package names."
            )
            raise SystemExit(msg)
        selection.explicit_groups.add(group)
        selection.dependency_group_packages.setdefault(group, set()).add(pkg)
        return
    group = rest
    selection.explicit_groups.add(group)
    selection.dependency_groups.add(group)


def validate_target_selection(selection: TargetSelection) -> None:
    if selection.update_dependencies and selection.dependency_packages:
        msg = (
            "Conflicting targets: `dependencies` cannot be used together with "
            "`dependencies:<package>` or `dependencies.<package>`."
        )
        raise SystemExit(msg)
    if selection.update_dependency_groups and (
        selection.dependency_groups or selection.dependency_group_packages
    ):
        msg = (
            "Conflicting targets: `dependency-groups` cannot be used together with "
            "group-specific selectors."
        )
        raise SystemExit(msg)
    overlap = selection.dependency_groups & set(selection.dependency_group_packages)
    if overlap:
        groups = ", ".join(sorted(overlap))
        msg = (
            "Conflicting targets for group(s): "
            f"{groups}. Do not combine `dependency-groups.<group>` with "
            "`dependency-groups.<group>:<package>` for the same group."
        )
        raise SystemExit(msg)


def is_package_selected(selection: TargetSelection, location: str, package: str) -> bool:
    normalized_package = package.lower()
    if location == "project.dependencies":
        if selection.update_dependencies:
            return True
        if selection.dependency_packages:
            return normalized_package in selection.dependency_packages
        return False
    if location.startswith("dependency-groups."):
        group = location.split(".", 1)[1]
        if selection.update_dependency_groups:
            return True
        if group in selection.dependency_groups:
            return True
        selected_packages = selection.dependency_group_packages.get(group)
        if selected_packages is not None:
            return normalized_package in selected_packages
        return False
    return True


def list_has_direct_dependencies(line: str) -> bool:
    for quoted in QUOTED_RE.finditer(line):
        value = quoted.group(2)
        if SPEC_RE.fullmatch(value):
            return True
    return False


def maybe_warn_for_empty_explicit_group(
    selection: TargetSelection,
    location: str,
    *,
    saw_direct_dependencies: bool,
) -> None:
    if saw_direct_dependencies or not location.startswith("dependency-groups."):
        return
    group = location.split(".", 1)[1]
    if group not in selection.explicit_groups:
        return
    print(
        f"Warning: `{location}` has no direct dependencies to update "
        "(likely only include-group entries).",
    )


def parse_operators_env(raw: str | None) -> set[str]:
    if raw is None or not raw.strip():
        return set(DEFAULT_OPERATORS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = (
            '`BUMPI_UPDATE_OPERATORS` must be a JSON list[str], for example: ["==",">="]'
        )
        raise SystemExit(msg) from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        msg = (
            '`BUMPI_UPDATE_OPERATORS` must be a JSON list[str], for example: ["==",">="]'
        )
        raise SystemExit(msg)
    selected = {item.strip() for item in parsed if item.strip()}
    if not selected:
        return set(DEFAULT_OPERATORS)
    unknown = selected - SUPPORTED_OPERATORS
    if unknown:
        supported = ", ".join(sorted(SUPPORTED_OPERATORS))
        unknown_items = ", ".join(sorted(unknown))
        msg = f"Unknown operators: {unknown_items}. Supported values: {supported}"
        raise SystemExit(msg)
    return selected


def main() -> None:
    selected_targets = parse_targets_env(getenv("BUMPI_UPDATE_TARGETS"))
    selected_operators = parse_operators_env(getenv("BUMPI_UPDATE_OPERATORS"))
    root = resolve_root()
    pyproject = root / "pyproject.toml"

    if not pyproject.is_file():
        msg = f"`pyproject.toml` not found under `{root}`."
        raise SystemExit(msg)

    text = pyproject.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    current_section = ""
    inside_target_list = False
    target_list_depth = 0
    current_location = ""
    current_list_has_direct_dependencies = False
    cache: dict[str, str | None] = {}
    updates: list[Update] = []
    out_lines: list[str] = []

    for line in lines:
        section_match = SECTION_RE.match(line)
        if section_match:
            current_section = section_match.group(1).strip()
            inside_target_list = False
            target_list_depth = 0
            current_location = ""
            out_lines.append(line)
            continue

        if not inside_target_list:
            current_location = detect_target_location(
                current_section,
                line,
                selected_targets,
            )
            if current_location:
                inside_target_list = True
                target_list_depth = 0
                current_list_has_direct_dependencies = False

        if not inside_target_list:
            out_lines.append(line)
            continue

        new_line, line_updates = bump_line(
            line,
            current_location,
            cache,
            selected_operators,
            selected_targets,
        )
        current_list_has_direct_dependencies = (
            current_list_has_direct_dependencies or list_has_direct_dependencies(line)
        )
        out_lines.append(new_line)
        updates.extend(line_updates)
        target_list_depth += bracket_delta(line)
        if target_list_depth <= 0:
            maybe_warn_for_empty_explicit_group(
                selected_targets,
                current_location,
                saw_direct_dependencies=current_list_has_direct_dependencies,
            )
            inside_target_list = False
            target_list_depth = 0
            current_location = ""
            current_list_has_direct_dependencies = False

    new_text = "".join(out_lines)
    if new_text != text:
        pyproject.write_text(new_text, encoding="utf-8")

    render_updates(updates)
    if updates and has_supported_lock(root):
        run_lock_upgrade(root)


def detect_target_location(
    section: str,
    line: str,
    selected_targets: TargetSelection,
) -> str:
    if (
        section == "project"
        and (
            selected_targets.update_dependencies
            or bool(selected_targets.dependency_packages)
        )
        and PROJECT_DEPENDENCIES_RE.match(line)
    ):
        return "project.dependencies"
    if (
        section == "build-system"
        and selected_targets.update_build_system_requires
        and BUILD_REQUIRES_RE.match(line)
    ):
        return "build-system.requires"
    if section == "dependency-groups":
        group_match = GROUP_LIST_RE.match(line)
        if group_match:
            group = group_match.group(2)
            if selected_targets.update_dependency_groups:
                return f"dependency-groups.{group}"
            if group in selected_targets.dependency_groups:
                return f"dependency-groups.{group}"
            if group in selected_targets.dependency_group_packages:
                return f"dependency-groups.{group}"
    return ""


def bracket_delta(line: str) -> int:
    sanitized = QUOTED_RE.sub("", line)
    return sanitized.count("[") - sanitized.count("]")


def run_lock_upgrade(root: Path) -> None:
    print("Running: uv lock --upgrade")
    run_checked(["uv", "lock", "--upgrade"], root)


def has_supported_lock(root: Path) -> bool:
    return any((root / lock_name).is_file() for lock_name in SUPPORTED_LOCKS)


def run_checked(command: list[str], cwd: Path) -> None:
    try:
        subprocess.run(  # noqa: S603
            command,
            cwd=cwd,
            check=True,
        )
    except FileNotFoundError as exc:
        msg = f"Failed to run `{command[0]}`: command not found."
        raise SystemExit(msg) from exc
    except subprocess.CalledProcessError as exc:
        joined = " ".join(command)
        msg = f"`{joined}` failed with exit code {exc.returncode}."
        raise SystemExit(msg) from exc


if __name__ == "__main__":
    main()
