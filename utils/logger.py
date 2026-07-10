"""
Simple logger stub for sentinel modules.

Currently the scanners and main use direct print for speed + simplicity
(keeps output clean and dependency-free for the core mission tool).
Replace with real logging if/when we add file output or levels.
"""

import logging

# Basic root config if anyone does import logging.getLogger
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("sentinel")
