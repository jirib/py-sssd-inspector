import sys
import yaml
from importlib import resources

def load_patterns() -> list[dict[str, str]]:
    """
    Loads and validates the error pattern list exclusively from the bundled YAML file
    asset.
    """
    try:
        # Safely resolve and open the asset inside the installed package directory
        traversable = resources.files(
            "sssd_inspector.log_inspector"
        ).joinpath("sssd_error_patterns.yaml")
        with traversable.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading built-in sssd_error_patterns.yaml: {e}", file=sys.stderr)
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
        file=sys.stderr
    )
    sys.exit(1)
