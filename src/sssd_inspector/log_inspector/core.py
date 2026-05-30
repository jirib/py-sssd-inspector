import sys

from pathlib import Path
from threading import RLock

from ..anonymizer import anonymize_line

# TODO: combine patterns into a single regex
def process_single_file(
    file_path: Path,
    patterns: list[dict[str, str]],
    max_lines: int,
    master_registry: dict,
    registry_lock: RLock,  # Explicitly typed as RLock
    noanonymize: bool
) -> dict[str, list[str]]:
    """
    Worker function: Extracts matches and handles line anonymization conditional gates.
    """
    local_results: dict[str, list[str]] = {}
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean_line = line.rstrip("\n")

                for item in patterns:
                    pattern = item.get("pattern")

                    if pattern and pattern in clean_line:
                        if noanonymize:
                            processed_line = clean_line
                        else:
                            processed_line = anonymize_line(
                                clean_line,
                                master_registry,
                                registry_lock
                            )

                        if pattern not in local_results:
                            local_results[pattern] = []

                        if processed_line not in local_results[pattern]:
                            local_results[pattern].append(processed_line)

                            if len(local_results[pattern]) > max_lines:
                                local_results[pattern].pop(0)
                        break
    except Exception as e:
        print(f"Warning: Skipping file '{file_path}': {e}", file=sys.stderr)

    return local_results
