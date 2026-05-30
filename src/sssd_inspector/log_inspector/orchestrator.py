import sys
import threading

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .core import process_single_file

def process_logs_concurrently(
    log_dir: Path,
    patterns: list[dict[str, str]],
    log_glob: str,
    max_lines: int,
    noanonymize: bool,
    progress_callback: Callable[[int, int], None] | None = None
) -> tuple[dict[Path, dict[str, list[str]]], dict]:
    """
    Streams file jobs and populates collections, signaling progress via a callback.
    """
    log_dir_path = Path(log_dir)

    if not log_dir_path.is_dir():
        print(f"Error: Log directory '{log_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    master_results: dict[Path, dict[str, list[str]]] = {}
    master_registry = {
        "hostnames": {}, "ips": {}, "ipv6s": {}, "emails": {}, "domains": {},
        "global_sub_counter": 0, "sub_mappings": {}
    }
    registry_lock = threading.RLock()

    with ThreadPoolExecutor() as executor:
        futures = {}

        for path in log_dir_path.rglob(log_glob):
            if path.is_file():
                if progress_callback:
                    cb = progress_callback
                    cb(0, 1)

                    future = executor.submit(
                        process_single_file, path, patterns, max_lines,
                        master_registry, registry_lock, noanonymize
                    )
                    future.add_done_callback(lambda f: cb(1, 0))
                else:
                    future = executor.submit(
                        process_single_file, path, patterns, max_lines,
                        master_registry, registry_lock, noanonymize
                    )

                futures[future] = path

        if not futures:
            return master_results, master_registry

        for future in as_completed(futures):
            file_path = futures[future]
            try:
                local_file_results = future.result()
                if local_file_results:
                    master_results[file_path] = local_file_results
            except Exception as e:
                print(f"Error processing {file_path.name}: {e}", file=sys.stderr)

    return master_results, master_registry
