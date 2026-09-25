import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bootstrap import bootstrap  # noqa: E402
from common.workspace import Workspace  # noqa: E402
from vendor.sign import release  # noqa: E402


@pytest.fixture
def ws(tmp_path) -> Workspace:
    w = Workspace(tmp_path / "ws")
    bootstrap(w)
    return w


@pytest.fixture
def released(ws):
    """A legitimate signed release v1.0.0, copied to the customer download area."""
    _, _, reg_a, reg_m = release(ws, "1.0.0")
    a = Path(shutil.copy2(reg_a, ws.downloads_dir / reg_a.name))
    m = Path(shutil.copy2(reg_m, ws.downloads_dir / reg_m.name))
    return ws, a, m
