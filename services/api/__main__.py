"""Run the CertStream API with ``python -m services.api``."""

import uvicorn

from .config import API_HOST, API_PORT, API_WORKERS

if __name__ == "__main__":
    uvicorn.run(
        "services.api.main:app",
        host=API_HOST,
        port=API_PORT,
        workers=API_WORKERS,
        log_level="info",
    )
