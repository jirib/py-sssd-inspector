import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import yaml
from tqdm import tqdm

from sssd_inspector.anonymize import anonymize_line


def load_patterns(yaml_path):
    """Loads and validates the error pattern list from the YAML file."""
    try:
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading YAML file '{yaml_path}': {e}", file=sys.stderr)
        sys.exit(1)

    if isinstance(data, dict):
        if "SSSD_ERROR_PATTERNS" in data:
            return data["SSSD_ERROR_PATTERNS"]
        for value in data.values():
            if isinstance(value, list):
                return value
    elif isinstance(data, list):
        return data

    print("Error: Invalid YAML structure. Expected a list of patterns.", file=sys.stderr)
    sys.exit(1)


def process_single_file(file_path, patterns, max_lines, master_registry, registry_lock, noanonymize):
    """Worker function: Extracts matches and handles line anonymization conditional gates."""
    local_results = {}
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
                            processed_line = anonymize_line(clean_line, master_registry, registry_lock)
                        
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


def process_logs_concurrently(log_dir, patterns, log_glob, max_lines, noanonymize):
    """Streams file jobs and populates structural match collections."""
    log_dir_path = Path(log_dir)

    if not log_dir_path.is_dir():
        print(f"Error: Log directory '{log_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    master_results = {}
    master_registry = {
        "hostnames": {}, "ips": {}, "ipv6s": {}, "emails": {}, "domains": {},
        "global_sub_counter": 0, "sub_mappings": {}
    }
    registry_lock = threading.RLock()

    with ThreadPoolExecutor() as executor:
        pbar = tqdm(desc="Analyzing logs", unit="file", total=0, file=sys.stderr)
        futures = {}

        for path in log_dir_path.rglob(log_glob):
            if path.is_file():
                pbar.total += 1
                future = executor.submit(
                    process_single_file, path, patterns, max_lines, 
                    master_registry, registry_lock, noanonymize
                )
                future.add_done_callback(lambda f: pbar.update(1))
                futures[future] = path

        if pbar.total == 0:
            pbar.close()
            return master_results, master_registry

        for future in as_completed(futures):
            file_path = futures[future]
            try:
                local_file_results = future.result()
                if local_file_results:
                    master_results[file_path] = local_file_results
            except Exception as e:
                print(f"Error processing {file_path.name}: {e}", file=sys.stderr)
                
        pbar.close()

    return master_results, master_registry