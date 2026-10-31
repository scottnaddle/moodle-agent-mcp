import logging
import os
import sys

import uvicorn

from .server import create_app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        app = create_app()
    except RuntimeError as exc:
        logging.getLogger("moodle_mcp").error("%s", exc)
        sys.exit(1)
    port = int(os.environ.get("MCP_PORT", "8791"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info", proxy_headers=True)


if __name__ == "__main__":
    main()
