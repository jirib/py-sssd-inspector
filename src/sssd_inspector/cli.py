import argparse
import io
import pydoc
import sys

from pathlib import Path

from sssd_inspector.anonymize import anonymize_log_filename
from sssd_inspector.inspect import load_patterns, process_logs_concurrently


def main():
    default_yaml = Path(__file__).parent / "data" / "sssd_error_patterns.yaml"
    parser = argparse.ArgumentParser(
        description="Concurrently scan logs, anonymize metrics hierarchically, and output summaries."
    )
    parser.add_argument("--logdir", required=True, help="Path to logs directory")
    parser.add_argument("--error-patterns", default=str(default_yaml), help="Path to YAML pattern file")
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