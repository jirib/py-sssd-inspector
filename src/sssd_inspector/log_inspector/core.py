import sys
from pathlib import Path
from threading import RLock

from ..anonymizer import anonymize_line


def process_single_file(
    file_path: Path,
    search_strings: list[str],
    max_lines: int,
    master_registry: dict,
    registry_lock: RLock,
    noanonymize: bool
) -> dict[str, list[str]]:
    """
    Scans a single log file using fast literal substring matching and applies
    late-anonymization only to the final retained lines.
    """
    local_results: dict[str, list[str]] = {}

    if not search_strings:
        return local_results

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean_line = line.rstrip("\n")

                for search_string in search_strings:
                    if search_string in clean_line:
                        local_results.setdefault(search_string, [])
                        if clean_line not in local_results[search_string]:
                            local_results[search_string].append(clean_line)
                            if len(local_results[search_string]) > max_lines:
                                local_results[search_string].pop(0)
    except Exception as e:
        print(f"Warning: Skipping file '{file_path}': {e}", file=sys.stderr)
        return local_results

    if noanonymize or not local_results:
        return local_results

    anonymized_results: dict[str, list[str]] = {}

    for pattern, raw_lines in local_results.items():
        anonymized_results[pattern] = []
        for raw_line in raw_lines:
            processed_line = anonymize_line(raw_line, master_registry, registry_lock)

            if processed_line not in anonymized_results[pattern]:
                anonymized_results[pattern].append(processed_line)

    return anonymized_results
