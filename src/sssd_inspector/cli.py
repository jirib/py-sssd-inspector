import argparse
import io
import pydoc
import sys
from tqdm import tqdm

from sssd_inspector.anonymizer import anonymize_log_filename
from sssd_inspector.log_inspector import load_patterns, process_logs_concurrently


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Concurrently scan logs, anonymize metrics hierarchically,"
        "and output summaries."
    )
    parser.add_argument(
        "--log-dir",
        required=True,
        help="Path to logs directory"
    )
    parser.add_argument(
        "--log-glob",
        default="*",
        help="Glob filter string patterns"
    )
    parser.add_argument(
        "--last-lines",
        type=int,
        default=5,
        help="Max trace lines limit"
    )
    parser.add_argument(
        "--nopager",
        action="store_true",
        help="Disable pager system output"
    )
    parser.add_argument(
        "--noanonymize",
        action="store_true",
        help="Disable text and filename anonymization"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print debug mapping token to stderr"
    )

    args = parser.parse_args()
    patterns = load_patterns()

    # Set up UI elements exclusively at the CLI boundary
    pbar = tqdm(desc="Analyzing logs", unit="file", total=0, file=sys.stderr)

    def ui_driver(advance: int, total_add: int) -> None:
        if total_add:
            pbar.total += total_add
        if advance:
            pbar.update(advance)

    try:
        results, registry = process_logs_concurrently(
            log_dir=args.log_dir,
            patterns=patterns,
            log_glob=args.log_glob,
            max_lines=args.last_lines,
            noanonymize=args.noanonymize,
            progress_callback=ui_driver  # Handing the UI controller over to the engine
        )
    finally:
        pbar.close()  # Guarantees the terminal line breaks cleanly even on failure

    if not results:
        print("No matching log entries found.")
        return

    output_buffer = io.StringIO()

    for idx, (file_path, patterns_dict) in enumerate(results.items()):
        if args.noanonymize:
            filename_header = file_path.name
        else:
            filename_header = anonymize_log_filename(file_path.name)

        if idx > 0:
            output_buffer.write("\n")

        header_line = f"#== {filename_header} ".ljust(80, "=")[:80]
        output_buffer.write(f"{header_line}\n\n")

        # Use enumerate here too to cleanly space out patterns inside the same file
        for p_idx, (pattern, lines) in enumerate(sorted(patterns_dict.items())):
            if p_idx > 0:
                output_buffer.write("\n")

            output_buffer.write(f"- pattern: {pattern}\n")
            for line in lines:
                output_buffer.write(f"  {line}\n")

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
        sys.stderr.write(
            "\n[Verbose] Anonymization was disabled via --noanonymize. No data"
             " telemetry was mapped.\n"
        )


if __name__ == "__main__":
    main()
