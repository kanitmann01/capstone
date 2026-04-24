from __future__ import annotations

"""
Application entry point.

Imports the configured FastAPI ``app`` and launches Uvicorn when executed
directly. In production, prefer invoking ``uvicorn`` from the command line
rather than running this module.
"""

from app.api import app  # Project-local: FastAPI application instance with all routes mounted
from app.api import scan_service  # Project-local: active AppService singleton (imported to ensure early initialisation)


if __name__ == "__main__":
    import uvicorn  # Third-party: ASGI server implementation

    # Launch the development server on all interfaces at port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)
