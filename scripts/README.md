# Example invocations

All commands assume you have set `THREATRAY_API_KEY` and either `THREATRAY_REALM` (SaaS) or
`THREATRAY_API_URL` (on-prem). See the [top-level README](../README.md) for setup.

Run the scripts either with `uv run scripts/<script>.py ...` or from an activated venv with
`python3 scripts/<script>.py ...`.

## `get_report.py` — fetch the report of a sample or analysis

```
$ python3 get_report.py --hash 5128bb068a8ab072f70e24e50edbb76198f9ed7859534505cf62c067bb1221de
File name: EFT voucher_INV.5199_14.01.2021.exe
File type: Exe (PE, x86-32)
MD5: c3aa9cf0cc1155132139e619fded88e4
SHA1: 7a68d37d0b9c8bb49c40945e7cd7f8480d6ac635
SHA256: 5128bb068a8ab072f70e24e50edbb76198f9ed7859534505cf62c067bb1221de
Verdict: malicious
Threats: ['LokiPasswordStealer(PWS)']
Analysis creation time: 2021-01-14 17:20:33
Processes:
  Process #1: qtswfbffvjfj.exe [4256], Threats: []
  Process #2: qtswfbffvjfj.exe [2700], Threats: ['LokiPasswordStealer(PWS)']
IOCs:
  Domains: 1
  URLs: 1
  IPs: 2
  Files: 4
  Mutexes: 1
  Registry: 65
```

Use `--analysis <uuid>` to pick a specific analysis of a sample that has multiple.

## `list_submissions.py` — list recent submissions

```
$ python3 list_submissions.py
User  Created at                 Analysis ID                           File name     SHA256                                                            Verdict    Threats  Status
----  -------------------------  ------------------------------------  ------------  ----------------------------------------------------------------  ---------  -------  ------
bob   2026-04-15 19:35:00+00:00  00734149-d425-4a0b-90d3-425c7e7a3db7  sample1.exe   5fdecb2cba8d... (full SHA256)                                     malicious  Remcos   done
bob   2026-04-15 19:20:48+00:00  85e8122b-4437-47e0-9ce0-3510b846e8d2  sample2.doc   6bb1fa2c66f1... (full SHA256)                                     malicious  Emotet   done
```

Times are shown in UTC.

## `submit_sample.py` — submit a file for analysis

Dynamic analysis (default):

```
$ python3 submit_sample.py --file-path ~/samples/823df75bbaf05c3e536da59416298aa2 \
    --label my-analysis --wait
Submitted file for analysis, created 1 submission(s).
Waiting for analysis to complete.

Report for analysis #1:
File name: 823df75bbaf05c3e536da59416298aa2
Verdict: malicious
Threats: ['QakBot']
...
```

Static analysis of a raw binary:

```
$ python3 submit_sample.py --file-path ./shellcode.bin \
    --analysis-mode static --raw-binary-file-format raw \
    --raw-binary-cpu-architecture x86-64 \
    --raw-binary-image-base-address 0x400000
```

The `--raw-binary-*` flags are only considered when `--analysis-mode static` is set.

## `search.py` — search / retrohunt

Selectors: `--domain`, `--ip`, `--url`, `--mutex`, `--registry`, `--file`, `--retrohunt`,
`--process`, `--signature`, `--label`, `--yara`, `--verdict`, `--sample-name`, `--analysis-id`,
`--file-hash`, `--memory-hash`. Use `--scope {private,public,both}` to limit results.

```
$ python3 search.py --domain tuandat-vn.com
Query: domain: "tuandat-vn.com"
Found 22 matching analyses.
Threats:
  LokiPasswordStealer(PWS): 20
  Cryptorium: 1
  Pony: 1

$ python3 search.py --yara "CAPE_Lumma_1"
Query: yara: "CAPE_Lumma_1"
Found 15 matching analyses.
Threats:
  Lumma: 15

$ python3 search.py --verdict malicious --scope private
Query: verdict: "malicious"
Found 1000 matching analyses.
```

## `download_file.py` — download a sample by hash

```
$ python3 download_file.py --hash 5128bb068a8ab072f70e24e50edbb76198f9ed7859534505cf62c067bb1221de
Downloaded file to: 5128bb068a8ab072f70e24e50edbb76198f9ed7859534505cf62c067bb1221de.zip
```

The file is returned as a password-protected ZIP.
