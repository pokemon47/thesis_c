from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import psutil
except ModuleNotFoundError:  # pragma: no cover - optional runtime dependency
    psutil = None


@dataclass(slots=True)
class CommandMetrics:
    command: list[str]
    elapsed_s: float
    peak_memory_bytes: int
    return_code: int
    stdout: str
    stderr: str


def _process_tree_rss(pid: int) -> int:
    if psutil is None:
        return 0
    try:
        root = psutil.Process(pid)
    except Exception:
        return 0
    processes = [root]
    try:
        processes.extend(root.children(recursive=True))
    except Exception:
        pass
    rss = 0
    for proc in processes:
        try:
            rss += proc.memory_info().rss
        except Exception:
            continue
    return rss


def run_command_with_memory(
    command: list[str],
    cwd: str | Path | None = None,
    poll_interval_s: float = 0.05,
) -> CommandMetrics:
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    peak = 0
    while process.poll() is None:
        peak = max(peak, _process_tree_rss(process.pid))
        time.sleep(poll_interval_s)

    stdout, stderr = process.communicate()
    elapsed = time.perf_counter() - started
    peak = max(peak, _process_tree_rss(process.pid))
    return CommandMetrics(
        command=command,
        elapsed_s=elapsed,
        peak_memory_bytes=peak,
        return_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )
