#!/usr/bin/env python3
import argparse
import io
import os
import sys
import tarfile
from pathlib import Path

def dump_log_file(log_path_str: str, lines: list[str], output_dir: Path) -> None:
    """
    Dumps isolated log lines back to a structured tree layout under the target output directory.
    """
    if not log_path_str:
        return

    if not lines:
        print(f"No data to save for {log_path_str}. Skipping.")
        return

    print(f"Processing {log_path_str}, ", end="")

    path_obj = Path(log_path_str)

    try:
        relative_path = path_obj.relative_to("/var/log")
    except ValueError:
        # Fallback if the path string doesn't start with /var/log
        relative_path = path_obj.relative_to(path_obj.anchor)

    new_path = output_dir / relative_path

    new_path.parent.mkdir(parents=True, exist_ok=True)

    new_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"saving {len(lines)} lines to {new_path}.")


def parse_sssd_stream(stream_iterable, output_dir: Path) -> None:
    """
    Loops line-by-line through any text generator stream matching the combined dump layout.
    """
    current_path = ""
    current_lines = []

    for line in stream_iterable:
        line_str = line.rstrip("\r\n")

        if line_str.startswith("#=="):
            continue

        if line_str.startswith("# /var/log/sssd"):
            if current_path:
                dump_log_file(current_path, current_lines, output_dir)

            current_lines = []
            _, _, path_part = line_str.partition(" ")
            if path_part:
                current_path = path_part.strip()
            continue
        else:
            current_lines.append(line_str)

    if current_path:
        dump_log_file(current_path, current_lines, output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Split a unified sssd.txt support output file back into isolated component logs."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--supportconfig",
        type=Path,
        help="Path to a compressed SUSE supportconfig archive (.tar.gz, .tgz, .txz)"
    )
    group.add_argument(
        "--sssd-txt-file",
        type=Path,
        help="Direct filesystem path to an already extracted standalone sssd.txt file"
    )

    default_tmp = os.environ.get("TMPDIR", "/tmp")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(default_tmp),
        help=f"Directory context where logs will be split (defaults to $TMPDIR: '{default_tmp}')"
    )

    args = parser.parse_args()
    output_dir = args.output_dir

    if args.sssd_txt_file:
        if not args.sssd_txt_file.exists():
            print(f"Error: File '{args.sssd_txt_file}' does not exist.", file=sys.stderr)
            sys.exit(1)

        with open(args.sssd_txt_file, "r", encoding="utf-8", errors="replace") as f:
            parse_sssd_stream(f, output_dir)

    elif args.supportconfig:
        if not args.supportconfig.exists():
            print(f"Error: Archive '{args.supportconfig}' does not exist.", file=sys.stderr)
            sys.exit(1)

        try:
            # Mode "r:*" unlocks automatic detection for gzip, bzip2, or xz algorithms
            with tarfile.open(args.supportconfig, mode="r:*") as tar:
                sssd_member = None

                for member in tar.getmembers():
                    if member.name.endswith("sssd.txt"):
                        sssd_member = member
                        break

                if not sssd_member:
                    print("Error: Could not locate 'sssd.txt' inside the archive.", file=sys.stderr)
                    sys.exit(1)

                f = tar.extractfile(sssd_member)
                if f is None:
                    print("Error: Failed to open file entry stream inside container.", file=sys.stderr)
                    sys.exit(1)

                with io.TextIOWrapper(f, encoding="utf-8", errors="replace") as text_stream:
                    parse_sssd_stream(text_stream, output_dir)

        except Exception as e:
            print(f"An error occurred while processing the archive container: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()