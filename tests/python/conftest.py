"""Pytest configuration. Adds python/ to sys.path so 'import recon' works."""
import sys
from pathlib import Path

# tests/python/conftest.py → repo_root = parents[2]
REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"

if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))
