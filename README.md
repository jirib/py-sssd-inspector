# py-sssd-inspector

## Installation

Install via `pipx install git+https://github.com/jirib/py-sssd-inspector`. The
minimum Python version is defined at [pyproject.toml](https://github.com/jirib/py-sssd-inspector/blob/main/pyproject.toml#L10).


## Usage

``` shell
$ sssd-inspector --help
usage: sssd-inspector [-h] --log-dir LOG_DIR [--log-glob LOG_GLOB] [--last-lines LAST_LINES] [--nopager] [--noanonymize] [-v]

Concurrently scan logs, anonymize metrics hierarchically,and output summaries.

options:
  -h, --help            show this help message and exit
  --log-dir LOG_DIR     Path to logs directory
  --log-glob LOG_GLOB   Glob filter string patterns
  --last-lines LAST_LINES
                        Max trace lines limit
  --nopager             Disable pager system output
  --noanonymize         Disable text and filename anonymization
  -v, --verbose         Print debug mapping token to stderr

$ sssd-inspector --logdir /tmp/sssd --log-glob '*.log' --nopager
Analyzing logs: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 21/21 [00:14<00:00,  1.42file/s]
#== sssd_nss.log.1 =============================================================

- pattern: SELINUX_getpeercon failed
  SELINUX_getpeercon failed [95][Operation not supported].

#== sssd_pam.log ===============================================================

- pattern: SELINUX_getpeercon failed
  SELINUX_getpeercon failed [95][Operation not supported].

#== ldap_child.log =============================================================

- pattern: cannot open shared object file
  (2026-05-27  6:01:46): [ldap_child[9805]] [sss_child_krb5_trace_cb] (0x4000): [9805] 1779861706.956650: Error loading plugin module spake: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: /usr/lib64/krb5/plugins/preauth/spake.so: cannot open shared object file: No such file or directory
  (2026-05-27  6:01:53): [ldap_child[9806]] [sss_child_krb5_trace_cb] (0x4000): [9806] 1779861713.377162: Error loading plugin module pkinit: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/pkinit.so]: /usr/lib64/krb5/plugins/preauth/pkinit.so: cannot open shared object file: No such file or directory
  (2026-05-27  6:01:53): [ldap_child[9806]] [sss_child_krb5_trace_cb] (0x4000): [9806] 1779861713.377163: Error loading plugin module spake: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: /usr/lib64/krb5/plugins/preauth/spake.so: cannot open shared object file: No such file or directory
  (2026-05-27  6:01:53): [ldap_child[9807]] [sss_child_krb5_trace_cb] (0x4000): [9807] 1779861713.658316: Error loading plugin module pkinit: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/pkinit.so]: /usr/lib64/krb5/plugins/preauth/pkinit.so: cannot open shared object file: No such file or directory
  (2026-05-27  6:01:53): [ldap_child[9807]] [sss_child_krb5_trace_cb] (0x4000): [9807] 1779861713.658317: Error loading plugin module spake: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: /usr/lib64/krb5/plugins/preauth/spake.so: cannot open shared object file: No such file or directory

#== sssd_nss.log ===============================================================

- pattern: Data Provider Error:
  (2026-05-25 20:57:57): [nss] [sss_dp_get_account_domain_done] (0x0040): Data Provider Error: 3, 1432158301
  (2026-05-27  6:05:47): [nss] [sss_dp_get_account_domain_done] (0x0040): Data Provider Error: 3, 1432158301

- pattern: SELINUX_getpeercon failed
  SELINUX_getpeercon failed [95][Operation not supported].
...
```

## Tools

`supportconfig2sssd-logs` is a helper tool to extract SSSD logs from
supportconfig, which can be inspected by `sssd-inspector`.
``` shell
$ supportconfig2sssd-logs --help
usage: supportconfig2sssd-logs [-h] (--supportconfig SUPPORTCONFIG | --sssd-txt-file SSSD_TXT_FILE) [--output-dir OUTPUT_DIR]

Split a unified sssd.txt support output file back into isolatedcomponent logs.

options:
  -h, --help            show this help message and exit
  --supportconfig SUPPORTCONFIG
                        Path to a compressed SUSE supportconfig archive (.tar.gz, .tgz, .txz)
  --sssd-txt-file SSSD_TXT_FILE
                        Direct filesystem path to an already extracted standalone sssd.txt file
  --output-dir OUTPUT_DIR
                        Directory context where logs will be split (defaults to $TMPDIR:'/tmp')
```

## Development

``` shell
$ mise run setup

$ mise run lint

$ mise run typecheck

$ mise run test

$ mise run install-global
```