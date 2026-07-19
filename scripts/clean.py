"""Remove only known, generated Patchwork development artifacts."""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    ROOT / ".pytest_cache",
    ROOT / ".mypy_cache",
    ROOT / ".ruff_cache",
    ROOT / "htmlcov",
    ROOT / "build",
    ROOT / "dist",
    ROOT / "apps" / "dashboard" / "dist",
    ROOT / "apps" / "dashboard" / ".vite",
)


def _remove_generated_directory(target: Path) -> None:
    """Remove a generated directory without following links or leaving the repository."""

    if target.is_symlink():
        raise RuntimeError(f"refusing to remove unexpected generated path: {target}")
    if not target.exists():
        return
    if ROOT not in target.parents:
        raise RuntimeError(f"refusing to remove path outside repository: {target}")
    resolved_target = target.resolve()
    if ROOT not in resolved_target.parents:
        raise RuntimeError(f"refusing to remove path outside repository: {target}")
    if not target.is_dir():
        raise RuntimeError(f"refusing to remove unexpected generated path: {target}")
    shutil.rmtree(target)
    print(f"removed {target.relative_to(ROOT)}")


def main() -> None:
    for target in TARGETS:
        _remove_generated_directory(target)
    for egg_info in (ROOT / "src").glob("*.egg-info"):
        _remove_generated_directory(egg_info)
    for coverage_file in ROOT.glob(".coverage*"):
        if coverage_file.is_file() and coverage_file.parent == ROOT:
            coverage_file.unlink()
            print(f"removed {coverage_file.name}")


if __name__ == "__main__":
    main()
