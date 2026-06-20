"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite (`pytest`).
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent

# Runtime deps the wheel itself declares in pyproject.toml [project.dependencies].
# Installing them into the fresh venv proves the wheel's metadata is complete and
# the declared dep chain is real and resolvable.  pyyaml is declared but not
# imported at runtime, so it is intentionally omitted here to keep the test
# focused on the actually-needed imports.
_RUNTIME_DEPS = [
    "nmap-wrapper @ git+https://github.com/bugsyhewitt/nmap-wrapper",
    "httpx>=0.27",
]

# Cross-cutting tests to exercise from the fresh-venv-installed wheel.
# These cover the full pipeline (recon → runner → JSON output, applicability
# filter, concurrency, --output-file flag, end-to-end smoke).  41 tests, ~0.3s.
_CROSS_CUTTING = [
    "tests/test_smoke.py",
    "tests/test_core.py",
    "tests/test_runner.py",
    "tests/test_recon.py",
    "tests/test_applicability.py",
    "tests/test_concurrency.py",
    "tests/test_output_file.py",
]


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _ensure_build_available():
    """Install `build` into the test-runner's venv on demand if absent."""
    try:
        _run([sys.executable, "-m", "build", "--version"])
    except subprocess.CalledProcessError:
        _run([sys.executable, "-m", "pip", "install", "--quiet", "build"])


def _expected_plugin_stems():
    from miasma.runner import available_plugins
    return sorted(available_plugins())


def _expected_plugin_count():
    from miasma.runner import available_plugins
    return len(available_plugins())


# ---------------------------------------------------------------------------
# Session-scoped fixtures — shared across all ship_gate tests in one run.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def wheel_artifacts(tmp_path_factory):
    """Build wheel + sdist; yield (wheel_path, sdist_path)."""
    _ensure_build_available()
    out = tmp_path_factory.mktemp("build-out")
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=str(REPO_ROOT),
    )
    wheels = list(out.glob("miasma-1.0.0-*.whl"))
    sdists = list(out.glob("miasma-1.0.0.tar.gz"))
    assert wheels, f"wheel not built; got: {sorted(p.name for p in out.iterdir())}"
    assert sdists, f"sdist not built; got: {sorted(p.name for p in out.iterdir())}"
    return wheels[0], sdists[0]


@pytest.fixture(scope="session")
def fresh_venv_dir(wheel_artifacts, tmp_path_factory):
    """Install the wheel into a brand-new isolated venv; yield the venv path.

    No --system-site-packages: the wheel install cannot fall back to any
    host-site copy of miasma.  --no-deps on the wheel install proves the wheel
    declares everything it needs; the follow-up dep installs prove the declared
    chain is real and resolvable.
    """
    wheel_path, _ = wheel_artifacts
    venv_dir = tmp_path_factory.mktemp("fresh-venv")
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    _run([str(pip), "install", "--quiet", str(wheel_path), "--no-deps"])
    _run([str(pip), "install", "--quiet", *_RUNTIME_DEPS])
    return venv_dir


# ---------------------------------------------------------------------------
# Ship-gate tests
# ---------------------------------------------------------------------------


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(wheel_artifacts):
    """`python -m build --wheel --sdist` produces both artifacts without error."""
    wheel_path, sdist_path = wheel_artifacts
    assert wheel_path.exists(), f"wheel missing: {wheel_path}"
    assert sdist_path.exists(), f"sdist missing: {sdist_path}"
    assert wheel_path.name.startswith("miasma-1.0.0-")
    assert sdist_path.name == "miasma-1.0.0.tar.gz"


@pytest.mark.ship_gate
def test_wheel_installs_and_version(fresh_venv_dir):
    """Entry-point resolves and `miasma --version` prints `miasma 1.0.0`."""
    miasma_bin = fresh_venv_dir / "bin" / "miasma"
    version = _run([str(miasma_bin), "--version"]).stdout.strip()
    assert version == "miasma 1.0.0", f"unexpected version output: {version!r}"


@pytest.mark.ship_gate
def test_wheel_list_plugins(fresh_venv_dir):
    """`miasma --list-plugins` in fresh venv matches editable-install output exactly."""
    miasma_bin = fresh_venv_dir / "bin" / "miasma"
    plugins_text = _run([str(miasma_bin), "--list-plugins"]).stdout
    installed_stems = sorted(line.strip() for line in plugins_text.splitlines() if line.strip())
    expected = _expected_plugin_stems()
    assert installed_stems == expected, (
        f"plugin list mismatch\ninstalled={installed_stems}\nexpected={expected}"
    )
    assert len(installed_stems) == 35, (
        f"expected exactly 35 plugins (current ship count); got {len(installed_stems)}"
    )


@pytest.mark.ship_gate
def test_wheel_version_importable(fresh_venv_dir):
    """`import miasma; assert miasma.__version__ == '1.0.0'` in fresh venv."""
    py = fresh_venv_dir / "bin" / "python"
    _run([str(py), "-c", "import miasma; assert miasma.__version__ == '1.0.0'"])


@pytest.mark.ship_gate
def test_installed_wheel_public_api(fresh_venv_dir):
    """Every public module and all 35 plugin modules import cleanly from fresh venv."""
    py = fresh_venv_dir / "bin" / "python"
    top_level = ["miasma.core", "miasma.cli", "miasma.recon", "miasma.runner"]
    plugin_modules = [f"miasma.plugins.{name}" for name in _expected_plugin_stems()]
    script = "; ".join(f"import {m}" for m in top_level + plugin_modules)
    _run([str(py), "-c", script])
    assert _expected_plugin_count() >= 34, (
        f"expected at least 34 plugins; got {_expected_plugin_count()}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_cross_cutting_tests(fresh_venv_dir):
    """Wheel-installed miasma, with pytest, passes the 41-test cross-cutting subset."""
    py = fresh_venv_dir / "bin" / "python"
    pip = fresh_venv_dir / "bin" / "pip"
    _run([str(pip), "install", "--quiet", "pytest>=8.0"])
    test_args = [str(py), "-m", "pytest", "-q", "--import-mode=importlib"]
    for rel in _CROSS_CUTTING:
        test_args.append(str(REPO_ROOT / rel))
    # Start from a clean env: strip working-tree venv activation so the fresh
    # venv's installed miasma is what the tests import, not the source tree.
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "VIRTUAL_ENV_PROMPT")}
    env["PATH"] = str(fresh_venv_dir / "bin") + ":" + env.get("PATH", "/usr/bin:/bin")
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        test_args,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, (
        f"cross-cutting tests failed in fresh venv\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    assert "passed" in proc.stdout, f"no 'passed' in pytest output:\n{proc.stdout}"


@pytest.mark.ship_gate
def test_version_source_of_truth_parity():
    """pyproject.toml `version` and `miasma.__version__` must agree."""
    import tomllib

    with open(REPO_ROOT / "pyproject.toml", "rb") as f:
        toml_version = tomllib.load(f)["project"]["version"]
    from miasma import __version__ as init_version

    assert toml_version == init_version, (
        f"version mismatch: pyproject.toml={toml_version!r}, "
        f"miasma/__init__.py={init_version!r}"
    )


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """CHANGELOG.md must exist at repo root and contain the v1.0.0 entry."""
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.is_file(), f"CHANGELOG.md not found at {changelog}"
    text = changelog.read_text()
    assert "## [1.0.0] - 2026-06-20" in text, (
        f"CHANGELOG.md missing '## [1.0.0] - 2026-06-20' entry; "
        f"found headers: {[line for line in text.splitlines() if line.startswith('## ')]}"
    )
