from __future__ import annotations
from pathlib import Path
import gzip
from typing import Iterator

def iter_log_lines(path: Path) -> Iterator[str]:
    """Iterate log lines from plain text or gzipped logs."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line:
                    yield line
    else:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line:
                    yield line