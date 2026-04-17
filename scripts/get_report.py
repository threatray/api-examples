import argparse
from datetime import datetime, timezone
from typing import Any

from threatray_client import ConfigError, get_client


def _fetch_and_print(path: str) -> None:
    client = get_client()
    resp = client.get(path)
    if resp.status_code != 200:
        try:
            body = resp.json()
            msg = body.get("description") or body.get("title") or resp.text
        except ValueError:
            msg = resp.text
        print(f"Failed to fetch report [{resp.status_code}]: {msg}")
        return
    print_report(resp.json())


def fetch_report_by_hash(sample_hash: str, analysis_id: str | None = None) -> None:
    if analysis_id:
        _fetch_and_print(f"/v1/samples/{sample_hash}/analyses/{analysis_id}")
    else:
        _fetch_and_print(f"/v1/samples/{sample_hash}")


def fetch_report_by_analysis(analysis_id: str) -> None:
    _fetch_and_print(f"/v1/analyses/{analysis_id}")


def print_report(report: dict[str, Any]) -> None:
    sample = report["sample"]
    analysis = report["analysis"]
    print(f"File name: {sample['file_name']}")
    print(f"File type: {sample['file_type']}")
    print(f"MD5: {sample['hash_md5']}")
    print(f"SHA1: {sample['hash_sha1']}")
    print(f"SHA256: {sample['hash_sha256']}")
    print(f"Verdict: {analysis['verdict']}")
    print(f"Threats: {[t['label'] for t in analysis['threats']]}")
    print(f"Analysis creation time: {datetime.fromtimestamp(analysis['creation_time'], tz=timezone.utc)}")

    processes = report.get("processes") or []
    if processes:
        print("Processes:")
        for process in processes:
            print(
                f"  Process #{process['process_id']}: {process['name']} [{process['pid']}], "
                f"Threats: {[t['label'] for t in process['threats']]}"
            )

    ioc = report.get("ioc") or {}
    if ioc:
        print("IOCs:")
        print(f"  Domains: {len(ioc.get('domains', []))}")
        print(f"  URLs: {len(ioc.get('urls', []))}")
        print(f"  IPs: {len(ioc.get('ips', []))}")
        print(f"  Files: {len(ioc.get('files', []))}")
        print(f"  Mutexes: {len(ioc.get('mutexes', []))}")
        print(f"  Registry: {len(ioc.get('registry', []))}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show the report of a sample or analysis.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--hash", type=str, help="Hash (MD5, SHA1, SHA256) of the sample.")
    target.add_argument("--analysis", type=str, help="Analysis UUID.")

    args = parser.parse_args()

    try:
        if args.hash:
            fetch_report_by_hash(args.hash)
        else:
            fetch_report_by_analysis(args.analysis)
    except ConfigError as e:
        raise SystemExit(f"error: {e}")
