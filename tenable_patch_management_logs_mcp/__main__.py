"""Process entrypoint: serve the TPM log tools over stdio.

    uv run python -m tenable_patch_management_logs_mcp
"""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    main()
