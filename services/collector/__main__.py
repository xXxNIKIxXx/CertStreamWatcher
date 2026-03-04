"""Allow running the collector as ``python -m services.collector``."""

import asyncio

from .certstream_service import main

if __name__ == "__main__":
    asyncio.run(main())
