# py-sssd-inspector

## Installation

Install via `pipx install git+https://github.com/jirib/py-sssd-inspector`. The
minimum Python version is defined at [pyproject.toml](https://github.com/jirib/py-sssd-inspector/blob/main/pyproject.toml#L10).


## Usage

``` shell
$ sssd-inspector --logdir /tmp/sssd --log-glob '*.log' --nopager
Analyzing logs: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 8/8 [00:35<00:00,  4.45s/file]
#== krb5_child.log =============================================================

- pattern: Server not found in Kerberos database
  - (2026-05-27  6:02:16): [krb5_child[9841]] [map_krb5_error] (0x0020): 1853: [-1765328377][Server not found in Kerberos database]
  - (2026-05-27  6:02:59): [krb5_child[10018]] [sss_child_krb5_trace_cb] (0x4000): [10018] 1779861779.521170: TGS request result: -1765328377/Server not found in Kerberos database
  - (2026-05-27  6:02:59): [krb5_child[10018]] [sss_child_krb5_trace_cb] (0x4000): [10018] 1779861779.521183: TGS request result: -1765328377/Server not found in Kerberos database
  - (2026-05-27  6:02:59): [krb5_child[10018]] [get_and_save_tgt] (0x0020): 1761: [-1765328377][Server not found in Kerberos database]
  - (2026-05-27  6:02:59): [krb5_child[10018]] [map_krb5_error] (0x0020): 1853: [-1765328377][Server not found in Kerberos database]
- pattern: Preauthentication failed
  - May 27 06:02:53 HOSTNAME krb5_child[9997]: Preauthentication failed
  - (2026-05-27  6:02:53): [krb5_child[9997]] [sss_child_krb5_trace_cb] (0x4000): [9997] 1779861773.165805: Received error from KDC: -1765328360/Preauthentication failed
  - (2026-05-27  6:02:53): [krb5_child[9997]] [sss_krb5_get_init_creds_password] (0x0020): 1647: [-1765328360][Preauthentication failed]
  - (2026-05-27  6:02:53): [krb5_child[9997]] [get_and_save_tgt] (0x0020): 1724: [-1765328360][Preauthentication failed]
  - (2026-05-27  6:02:53): [krb5_child[9997]] [map_krb5_error] (0x0020): 1853: [-1765328360][Preauthentication failed]
- pattern: [13][Permission denied]
  -    *  (2026-03-21 14:13:53): [gpo_child[13677]] [copy_smb_file_to_gpo_cache] (0x0020): smbc_getFunctionOpen failed [13][Permission denied]
  - (2026-03-21 14:13:53): [gpo_child[13677]] [perform_smb_operations] (0x0020): copy_smb_file_to_gpo_cache failed [13][Permission denied]
  - (2026-03-21 14:13:53): [gpo_child[13677]] [main] (0x0020): perform_smb_operations failed.[13][Permission denied].
  -    *  (2026-03-21 14:13:53): [gpo_child[13677]] [perform_smb_operations] (0x0020): copy_smb_file_to_gpo_cache failed [13][Permission denied]
  -    *  (2026-03-21 14:13:53): [gpo_child[13677]] [main] (0x0020): perform_smb_operations failed.[13][Permission denied].
- pattern: cannot open shared object file
  - (2026-05-27  6:02:16): [krb5_child[9841]] [sss_child_krb5_trace_cb] (0x4000): [9841] 1779861736.343785: Error loading plugin module spake: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: /usr/lib64/krb5/plugins/preauth/spake.so: cannot open shared object file: No such file or directory
  - (2026-05-27  6:02:53): [krb5_child[9997]] [sss_child_krb5_trace_cb] (0x4000): [9997] 1779861773.165772: Error loading plugin module pkinit: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/pkinit.so]: /usr/lib64/krb5/plugins/preauth/pkinit.so: cannot open shared object file: No such file or directory
  - (2026-05-27  6:02:53): [krb5_child[9997]] [sss_child_krb5_trace_cb] (0x4000): [9997] 1779861773.165773: Error loading plugin module spake: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: /usr/lib64/krb5/plugins/preauth/spake.so: cannot open shared object file: No such file or directory
  - (2026-05-27  6:02:59): [krb5_child[10018]] [sss_child_krb5_trace_cb] (0x4000): [10018] 1779861779.521060: Error loading plugin module pkinit: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/pkinit.so]: /usr/lib64/krb5/plugins/preauth/pkinit.so: cannot open shared object file: No such file or directory
  - (2026-05-27  6:02:59): [krb5_child[10018]] [sss_child_krb5_trace_cb] (0x4000): [10018] 1779861779.521061: Error loading plugin module spake: 2/unable to load plugin [/usr/lib64/krb5/plugins/preauth/spake.so]: /usr/lib64/krb5/plugins/preauth/spake.so: cannot open shared object file: No such file or directory
- pattern: not found in keytab
  - (2026-05-25 15:07:13): [krb5_child[25759]] [validate_tgt] (0x2000): Keytab entry with the realm of the credential not found in keytab. Using the last entry.
  - (2026-05-27  6:01:54): [krb5_child[9809]] [validate_tgt] (0x2000): Keytab entry with the realm of the credential not found in keytab. Using the last entry.
  - (2026-05-27  6:02:06): [krb5_child[9839]] [validate_tgt] (0x2000): Keytab entry with the realm of the credential not found in keytab. Using the last entry.
  - (2026-05-27  6:02:16): [krb5_child[9841]] [validate_tgt] (0x2000): Keytab entry with the realm of the credential not found in keytab. Using the last entry.
  - (2026-05-27  6:02:59): [krb5_child[10018]] [validate_tgt] (0x2000): Keytab entry with the realm of the credential not found in keytab. Using the last entry.
- pattern: TGT failed verification using key
  - (2026-05-25 15:07:13): [krb5_child[25759]] [validate_tgt] (0x0020): TGT failed verification using key for [RestrictedKrbHost/[REDACTED_USER]@example.com].
  - (2026-05-27  6:01:54): [krb5_child[9809]] [validate_tgt] (0x0020): TGT failed verification using key for [RestrictedKrbHost/[REDACTED_USER]@example.com].
  - (2026-05-27  6:02:06): [krb5_child[9839]] [validate_tgt] (0x0020): TGT failed verification using key for [RestrictedKrbHost/[REDACTED_USER]@example.com].
  - (2026-05-27  6:02:16): [krb5_child[9841]] [validate_tgt] (0x0020): TGT failed verification using key for [RestrictedKrbHost/[REDACTED_USER]@example.com].
  - (2026-05-27  6:02:59): [krb5_child[10018]] [validate_tgt] (0x0020): TGT failed verification using key for [RestrictedKrbHost/[REDACTED_USER]@example.com].

#== gpo_child.log ==============================================================

- pattern: Server not found in Kerberos database
  - May 27 06:02:06 HOSTNAME krb5_child[9839]: Server not found in Kerberos database
  - May 27 06:02:16 HOSTNAME krb5_child[9841]: Server not found in Kerberos database
  - May 27 06:02:16 HOSTNAME krb5_child[9841]: Server not found in Kerberos database
  - May 27 06:02:59 HOSTNAME krb5_child[10018]: Server not found in Kerberos database
  - May 27 06:02:59 HOSTNAME krb5_child[10018]: Server not found in Kerberos database
- pattern: Preauthentication failed
  - May 27 06:02:53 HOSTNAME krb5_child[9997]: Preauthentication failed
  - May 27 06:02:53 HOSTNAME krb5_child[9997]: Preauthentication failed
```

## Tools

- `tools/supportconfig2sssd-logs.py` is a helper tool to extract SSSD logs from
  supportconfig, which can be inspected by `sssd-inspector`.
  ``` shell
  $ SCRIPT_PATH="$(pipx runpip sssd-inspector show sssd-inspector | grep -Po '^Location: \K(.*)')/sssd_inspector/tools/supportconfig2sssd-logs.py"
  $ python3 "$SCRIPT_PATH" --help
  usage: supportconfig2sssd-logs.py [-h] (--supportconfig SUPPORTCONFIG | --sssd-txt-file SSSD_TXT_FILE) [--output-dir OUTPUT_DIR]

  Split a unified sssd.txt support output file back into isolated component logs.

  options:
    -h, --help            show this help message and exit
    --supportconfig SUPPORTCONFIG
                          Path to a compressed SUSE supportconfig archive (.tar.gz, .tgz, .txz)
    --sssd-txt-file SSSD_TXT_FILE
                          Direct filesystem path to an already extracted standalone sssd.txt file
    --output-dir OUTPUT_DIR
                        Directory context where logs will be split (defaults to $TMPDIR: '/tmp')
```