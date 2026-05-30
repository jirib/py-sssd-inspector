import re
import threading

SYSLOG_REGEX = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)(\S+)"
)
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(
    r"\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b|"
    r"\b(?:[a-f0-9]{1,4}:){1,7}:|"
    r"\b:(?::[a-f0-9]{1,4}){1,7}\b",
    re.IGNORECASE
)
EMAIL_REGEX = re.compile(
    r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
    re.IGNORECASE
)
DOMAIN_REGEX = re.compile(
    r"(?<!/)(?:^|(?<=_)|(?<=\s)|\b)"
    r"((?:[a-zA-Z0-9_-]+\.)+(?!(?:log|conf|txt|py|sh)\b)[a-zA-Z]{2,}\b)",
    re.IGNORECASE
)
FILE_REGEX = re.compile(r"^(sssd_)(.*?)(\.log.*)$", re.IGNORECASE)


def apply_case(template: str, original: str) -> str:
    """
    Helper to match the casing format of the original string input.
    """
    if original.isupper():
        return template.upper()
    if original and original[0].isupper():
        return template.capitalize()
    return template.lower()


def get_anon_domain(
        domain_str: str,
        registry: dict,
        lock: threading.RLock
) -> str:
    """
    Recursively maps multi-dot domains to nested subdomains while ignoring
    existing tokens.
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


def anonymize_log_filename(filename: str) -> str:
    """
    Masks the domain part of an sssd_<domain>.log filename.
    """
    if (
        not filename.startswith("sssd_")             # only process sssd_ prefixed logs
        or "." not in filename.partition(".log")[0]  # and, if no dot before .log, skip
    ):
        return filename

    match = FILE_REGEX.match(filename)

    if match:
        prefix = match.group(1)
        domain_part = match.group(2)
        extension_part = match.group(3)

        if "example.com" in domain_part.lower():
            return filename

        parts = domain_part.split(".")
        if len(parts) <= 2:
            anon_domain = apply_case("example.com", domain_part)
        else:
            root = apply_case("example.com", domain_part)
            sub_parts = parts[:-2]

            anon_parts = []
            for i, part in enumerate(reversed(sub_parts)):
                anon_parts.append(apply_case(f"sub{i}", part))

            anon_parts.reverse()
            anon_parts.append(root)
            anon_domain = ".".join(anon_parts)

        return f"{prefix}{anon_domain}{extension_part}"

    return filename


def anonymize_syslog_header(line: str, registry: dict, lock: threading.RLock) -> str:
    """
    Extracts and redacts syslog hostnames while preserving case layout.
    """
    if line[:1].isupper():  # a syslog line starts with a capitalized month name
        return line

    syslog_match = SYSLOG_REGEX.match(line)

    if syslog_match:
        prefix = syslog_match.group(1)
        hostname = syslog_match.group(2)
        anon_host = apply_case("hostname", hostname)

        with lock:
            registry["hostnames"][hostname] = anon_host
        line = prefix + anon_host + line[syslog_match.end():]
    return line


def anonymize_ipv4(line: str, registry: dict, lock: threading.RLock) -> str:
    """
    Finds and replaces standard IPv4 addresses.
    """
    if "." not in line:  # every IPv4 address contains a dot!
        return line

    ips = IPV4_REGEX.findall(line)
    if not ips:
        return line

    with lock:
        for ip in ips:
            registry["ips"][ip] = "XXX.XXX.XXX.XXX"

    return IPV4_REGEX.sub("XXX.XXX.XXX.XXX", line)


def anonymize_ipv6(line: str, registry: dict, lock: threading.RLock) -> str:
    """
    Finds and replaces shorthand and longform IPv6 targets.
    """
    if ":" not in line:  # every IPv6 address contains a colon!
        return line

    ips = IPV6_REGEX.findall(line)
    if not ips:
        return line

    with lock:
        for ip6 in ips:
            registry["ipv6s"][ip6] = "XXXX:XXXX::XXXX"

    return IPV6_REGEX.sub("XXXX:XXXX::XXXX", line)


def anonymize_emails(line: str, registry: dict, lock: threading.RLock) -> str:
    """
    Redacts complex email addresses, checking for nested user subdomains.
    """
    if "@" not in line:  # every email address contains an @ symbol!
        return line

    emails = EMAIL_REGEX.findall(line)
    if not emails:
        return line

    def preserve_email_case(match: re.Match) -> str:
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

    return EMAIL_REGEX.sub(preserve_email_case, line)


def anonymize_domains(line: str, registry: dict, lock: threading.RLock) -> str:
    """
    Identifies and handles dynamic infrastructure domains hierarchically.
    """
    if "." not in line:  # every domain contains a dot!
        return line

    domains = DOMAIN_REGEX.findall(line)
    if not domains:
        return line

    def preserve_domain_case(match: re.Match) -> str:
        return get_anon_domain(match.group(0), registry, lock)

    return DOMAIN_REGEX.sub(preserve_domain_case, line)


def anonymize_line(line: str, registry: dict, lock: threading.RLock) -> str:
    """
    Executes all structural anonymization helper routines sequentially.
    """
    line = anonymize_syslog_header(line, registry, lock)
    line = anonymize_ipv4(line, registry, lock)
    line = anonymize_ipv6(line, registry, lock)
    line = anonymize_emails(line, registry, lock)
    line = anonymize_domains(line, registry, lock)
    return line
