import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .core import process_single_file
from .patterns import extract_search_strings, load_patterns


def process_logs(
    log_dir: Path,
    log_glob: str,
    max_lines: int,
    noanonymize: bool,
    progress_callback: Callable[[int, int], None] | None = None
) -> tuple[dict[Path, dict[str, list[str]]], dict]:
    """
    Unified pipeline to process a single file or directory of logs.
    Automatically optimizes execution paths based on workload size.
    """
    raw_patterns = load_patterns()
    search_strings = extract_search_strings(raw_patterns)

    log_dir_path = Path(log_dir)
    files: list[Path] = []

    if log_dir_path.is_file():
        files = [log_dir_path]
    elif log_dir_path.is_dir():
        files = [p for p in log_dir_path.rglob(log_glob) if p.is_file()]
    else:
        print(f"Error: Target path '{log_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    master_results: dict[Path, dict[str, list[str]]] = {}
    master_registry = {
        "hostnames": {}, "ips": {}, "ipv6s": {}, "emails": {}, "domains": {},
        "global_sub_counter": 0, "sub_mappings": {}
    }

    if not files:
        return master_results, master_registry

    registry_lock = threading.RLock()

    if len(files) == 1:  # no concurrent overhead for a single file
        single_file = files[0]
        if progress_callback:
            progress_callback(0, 1)

        local_file_results = process_single_file(
            single_file, search_strings, max_lines,
            master_registry, registry_lock, noanonymize
        )
        if local_file_results:
            master_results[single_file] = local_file_results

        if progress_callback:
            progress_callback(1, 0)

    else:
        with ThreadPoolExecutor() as executor:
            futures = {}

            for path in files:
                if progress_callback:
                    cb = progress_callback
                    cb(0, 1)

                    future = executor.submit(
                        process_single_file, path, search_strings, max_lines,
                        master_registry, registry_lock, noanonymize
                    )
                    future.add_done_callback(lambda f: cb(1, 0))
                else:
                    future = executor.submit(
                        process_single_file, path, search_strings, max_lines,
                        master_registry, registry_lock, noanonymize
                    )

                futures[future] = path

            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    local_file_results = future.result()
                    if local_file_results:
                        master_results[file_path] = local_file_results
                except Exception as e:
                    print(f"Error processing {file_path.name}: {e}", file=sys.stderr)

    return master_results, master_registry
