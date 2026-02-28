from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repository root (which contains `custom_components/`) is importable
# regardless of how pytest is invoked or which import mode is active.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
