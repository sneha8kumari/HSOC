import os
import sys

# Ensure config directories are inside workspace
os.environ["YOLO_CONFIG_DIR"] = "./data"
os.environ["ULTRALYTICS_CONFIG_DIR"] = "./data"

# Preload FAISS on Windows before test collection to resolve C-extension DLL paths
try:
    import faiss  # noqa: F401
except Exception:
    pass
