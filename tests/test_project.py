"""Project-level hygiene tests: dependency declarations must not drift."""
import os
import re
import tomllib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _requirements_names():
    names = set()
    with open(os.path.join(REPO, "requirements.txt")) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[<>=!~ ]", line, maxsplit=1)[0].strip().lower()
            if name:
                names.add(name)
    return names


def _pyproject_names():
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
        data = tomllib.load(f)
    return {d.split(">=")[0].strip().lower() for d in data["project"]["dependencies"]}


def test_dependencies_in_sync():
    req, py = _requirements_names(), _pyproject_names()
    assert req == py, f"drift: only-in-requirements={req - py}, only-in-pyproject={py - req}"


def test_pytest_declared_in_dev_requirements():
    with open(os.path.join(REPO, "requirements-dev.txt")) as f:
        assert any("pytest" in line for line in f)