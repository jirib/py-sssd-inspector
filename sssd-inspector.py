#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pyyaml",
#     "tqdm",
# ]
# ///

# all credits for error patterns and descriptions go to https://github.com/davpuggioni

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import pydoc
from pathlib import Path
import re
import sys
import threading
import yaml
from tqdm import tqdm


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

    print(
        "Error: Invalid YAML structure. Expected a list of patterns.",
        file=sys.stderr,
    )
    sys.exit(1)


def apply_case(template: str, original: str) -> str:
    """Helper to match the casing format of the original string input."""
    if original.isupper():
        return template.upper()
    if original and original[0].isupper():
        return template.capitalize()
    return template.lower()


def get_anon_domain(domain_str: str, registry: dict, lock: threading.RLock) -> str:
    """
    Recursively maps and translates multi-dot domains to nested subdomains
    while completely ignoring existing anonymous 'example.com' tokens.
    """
    low_dom = domain_str.lower()
    
    if "example.com" in low_dom:
        return domain_str

    if "." not in domain_str:
        return domain_str

    with lock:
        if low_dom in registry["domains"]:
            return apply_case(registry["domains"][low_dom], domain_str)

        parts = domain_str.split(".")
        if len(parts) == 2:
            res = "example.com"
        else:
            parent = ".".join(parts[1:])
            anon_parent = get_anon_domain(parent, registry, lock)
            low_anon_parent = anon_parent.lower()

            sub_key = (parts[0].lower(), low_anon_parent)
            if sub_key not in registry["sub_mappings"]:
                idx = registry["global_sub_counter"]
                registry["sub_mappings"][sub_key] = f"sub{idx}"
                registry["global_sub_counter"] += 1

            sub_label = registry["sub_mappings"][sub_key]
            res = f"{sub_label}.{anon_parent}"

        registry["domains"][low_dom] = res.lower()
        return apply_case(res, domain_str)


# =========================================================================
# ISOLATED ANONYMIZATION COMPONENT FUNCTIONS (Ideal for Unit Testing)
# =========================================================================

def anonymize_log_filename(filename: str) -> str:
    """
    Splits log filename using the pattern: (sssd_)(until .log)(.log.*)
    and anonymizes the second group statelessly WITHOUT using a registry.
    """
    filename_regex = re.compile(r'^(sssd_)(.*?)(\.log.*)$', re.IGNORECASE)
    match = filename_regex.match(filename)
    
    if match:
        prefix = match.group(1)         # e.g., 'sssd_'
        domain_part = match.group(2)    # e.g., 'foo.bar.net'
        extension_part = match.group(3)  # e.g., '.log-20260524'
        
        # Guard: If domain part already contains anonymous structures, pass it through
        if "example.com" in domain_part.lower():
            return filename

        parts = domain_part.split('.')
        if len(parts) <= 2:
            anon_domain = apply_case("example.com", domain_part)
        else:
            root = apply_case("example.com", domain_part)
            sub_parts = parts[:-2]  # Isolate subdomains from the root (e.g., ['foo'])
            
            anon_parts = []
            # Positional mapping from right to left (rightmost gets sub0, next gets sub1...)
            for i, part in enumerate(reversed(sub_parts)):
                anon_parts.append(apply_case(f"sub{i}", part))
            
            anon_parts.reverse()    # Restore original reading sequence order
            anon_parts.append(root)
            anon_domain = ".".join(anon_parts)
            
        return f"{prefix}{anon_domain}{extension_part}"
        
    return filename


def anonymize_syslog_header(line: str, registry: dict, lock: threading.RLock) -> str:
    """Extracts and redacts syslog hostnames while preserving case layout."""
    syslog_regex = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)(\S+)')
    syslog_match = syslog_regex.match(line)
    
    if syslog_match:
        prefix = syslog_match.group(1)
        hostname = syslog_match.group(2)
        anon_host = apply_case("hostname", hostname)
            
        with lock:
            registry["hostnames"][hostname] = anon_host
        line = prefix + anon_host + line[syslog_match.end():]
    return line


def anonymize_ipv4(line: str, registry: dict, lock: threading.RLock) -> str:
    """Finds and replaces standard IPv4 addresses."""
    ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    with lock:
        for ip in ip_regex.findall(line):
            registry["ips"][ip] = "XXX.XXX.XXX.XXX"
    return ip_regex.sub("XXX.XXX.XXX.XXX", line)


def anonymize_ipv6(line: str, registry: dict, lock: threading.RLock) -> str:
    """Finds and replaces shorthand and longform IPv6 targets."""
    ipv6_regex = re.compile(
        r'\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b|'
        r'\b(?:[a-f0-9]{1,4}:){1,7}:|'
        r'\b:(?::[a-f0-9]{1,4}){1,7}\b', 
        re.IGNORECASE
    )
    with lock:
        for ip6 in ipv6_regex.findall(line):
            registry["ipv6s"][ip6] = "XXXX:XXXX::XXXX"
    return ipv6_regex.sub("XXXX:XXXX::XXXX", line)


def anonymize_emails(line: str, registry: dict, lock: threading.RLock) -> str:
    """Redacts complex email addresses, recursively checking for nested user subdomains."""
    email_regex = re.compile(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', re.IGNORECASE)

    def preserve_email_case(match):
        full_email = match.group(0)
        user_part, domain_part = full_email.split("@", 1)
        
        if "." in user_part:
            anon_user = get_anon_domain(user_part, registry, lock)
        else:
            anon_user = "[REDACTED_USER]"
        
        anon_domain = get_anon_domain(domain_part, registry, lock)
        anon_email = f"{anon_user}@{anon_domain}"
        
        with lock:
            registry["emails"][full_email] = anon_email
        return anon_email

    return email_regex.sub(preserve_email_case, line)


def anonymize_domains(line: str, registry: dict, lock: threading.RLock) -> str:
    """Identifies and handles dynamic infrastructure domains hierarchically."""
    domain_regex = re.compile(
        r'(?<!/)(?:^|(?<=_)|(?<=\s)|\b)((?:[a-zA-Z0-9_-]+\.)+(?!(?:log|conf|txt|py|sh)\b)[a-zA-Z]{2,}\b)',
        re.IGNORECASE
    )

    def preserve_domain_case(match):
        return get_anon_domain(match.group(0), registry, lock)

    return domain_regex.sub(preserve_domain_case, line)


def anonymize_line(line: str, registry: dict, lock: threading.RLock) -> str:
    """Executes all structural anonymization helper routines sequentially."""
    line = anonymize_syslog_header(line, registry, lock)
    line = anonymize_ipv4(line, registry, lock)
    line = anonymize_ipv6(line, registry, lock)
    line = anonymize_emails(line, registry, lock)
    line = anonymize_domains(line, registry, lock)
    return line

# =========================================================================


def process_single_file(file_path, patterns, max_lines, master_registry, registry_lock, noanonymize):
    """Worker function: Extracts matches and conditionally handles line anonymization."""
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


def main():
    parser = argparse.ArgumentParser(
        description="Concurrently scan logs, anonymize metrics hierarchically, and output summaries."
    )
    parser.add_argument("--logdir", required=True, help="Path to logs directory")
    parser.add_argument("--error-patterns", required=True, help="Path to YAML pattern file")
    parser.add_argument("--log-glob", default="*", help="Glob filter string patterns")
    parser.add_argument("--last-lines", type=int, default=5, help="Max trace lines limit")
    parser.add_argument("--nopager", action="store_true", help="Disable pager system output")
    parser.add_argument("--noanonymize", action="store_true", help="Disable text and filename anonymization")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print debug mapping token to stderr")

    args = parser.parse_args()

    patterns = load_patterns(args.error_patterns)
    results, registry = process_logs_concurrently(
        args.logdir, patterns, args.log_glob, args.last_lines, args.noanonymize
    )

    if not results:
        print(f"No matching log entries found.")
        return

    output_buffer = io.StringIO()
    
    for file_path, patterns_dict in results.items():
        if args.noanonymize:
            filename_header = file_path.name
        else:
            # Clean execution call wrapper: no registry or lock parameters passed
            filename_header = anonymize_log_filename(file_path.name)
        
        header_line = f"#== {filename_header} ".ljust(80, "=")[:80]
        output_buffer.write(f"{header_line}\n\n")
        
        for pattern, lines in patterns_dict.items():
            output_buffer.write(f"- pattern: {pattern}\n")
            for line in lines:
                output_buffer.write(f"  - {line}\n")
        output_buffer.write("\n")

    report_content = output_buffer.getvalue()

    if args.nopager:
        print(report_content, end="")
    else:
        pydoc.pager(report_content)

    if args.verbose and not args.noanonymize:
        sys.stderr.write("\n=== Anonymization Telemetry Registry (Verbose) ===\n")
        for category in ["hostnames", "ips", "ipv6s", "emails", "domains"]:
            mappings = registry[category]
            if mappings:
                sys.stderr.write(f"\nMasked {category.capitalize()}:\n")
                for original, replaced in sorted(mappings.items()):
                    sys.stderr.write(f"  - {original} -> {replaced}\n")
        sys.stderr.write("==================================================\n")
    elif args.verbose and args.noanonymize:
        sys.stderr.write("\n[Verbose] Anonymization was disabled via --noanonymize. No data telemetry was mapped.\n")


if __name__ == "__main__":
    main()
