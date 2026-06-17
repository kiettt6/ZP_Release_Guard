import sys
from pathlib import Path

import uvicorn


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
    uvicorn.run("zp_release_guard.api:app", host="0.0.0.0", port=8080)
