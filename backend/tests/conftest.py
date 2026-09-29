import sys
from pathlib import Path

# Ensure backend directory is in sys.path for test discovery and imports
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
