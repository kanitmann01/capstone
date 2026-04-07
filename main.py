from __future__ import annotations

from app.api import app
from app.api import scan_service


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
