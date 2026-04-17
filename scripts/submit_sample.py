import argparse
import time
from typing import Any

from get_report import fetch_report_by_analysis
from threatray_client import ConfigError, get_client


def parse_address(value: str) -> str:
    """Validate that a memory address is a decimal or hex number. Returned as-is for the API."""
    try:
        int(value, 0)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(f"Invalid address: {value!r}") from None
    return value


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    data: dict[str, Any] = {
        "analysis_mode": args.analysis_mode,
        "label": args.label,
        "timeout": args.timeout,
        "environments": args.environments,
        "enable_network": not args.disable_network,
        "priority": args.priority,
    }
    if args.analysis_mode == "static":
        data.update(
            {
                "raw_binary_file_format": args.raw_binary_file_format,
                "raw_binary_cpu_architecture": args.raw_binary_cpu_architecture,
                "raw_binary_image_base_address": args.raw_binary_image_base_address,
                "raw_binary_function_entry_point_detection_needed": args.raw_binary_function_entry_point_detection_needed,
                "raw_binary_function_file_offset": args.raw_binary_function_file_offset,
            }
        )
    return {k: v for k, v in data.items() if v is not None}


def submit_sample(args: argparse.Namespace) -> None:
    client = get_client()
    data = build_payload(args)

    with open(args.file_path, "rb") as f:
        resp = client.post(
            "/v1/submissions/samples",
            data=data,
            files={"file": f},
        )
    if resp.status_code != 201:
        try:
            msg = resp.json()["error"]["message"]
        except (ValueError, KeyError):
            msg = resp.text
        print(f"Failed to submit file for analysis: {msg}")
        return

    body = resp.json()
    submissions = body.get("submissions") or []
    if not submissions:
        print("No submissions were created (the file may be unsupported).")
        return

    print(f"Submitted file for analysis, created {len(submissions)} submission(s).")

    if not args.wait:
        return

    print(f"Waiting for analysis to complete (timeout: {args.wait_timeout}s).")
    is_done = [False] * len(submissions)
    deadline = time.monotonic() + args.wait_timeout
    while True:
        for idx, submission in enumerate(submissions):
            if is_done[idx]:
                continue
            task_resp = client.get(f"/v1/tasks/{submission['task_id']}")
            if task_resp.status_code != 200:
                continue
            status = task_resp.json()["status"]
            if status not in ("queued", "analyzing"):
                submission["status"] = status
                is_done[idx] = True
        if all(is_done):
            break
        if time.monotonic() > deadline:
            print("Timed out waiting for analyses to complete.")
            return
        time.sleep(5)

    for idx, submission in enumerate(submissions):
        print(f"\nReport for analysis #{idx + 1}:")
        if "analysis" in submission and submission["status"] == "done":
            fetch_report_by_analysis(submission["analysis"]["id"])
        else:
            print(f"Analysis status: {submission['status']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Submit a file for analysis.")
    parser.add_argument("--file-path", required=True, help="Path to the file (or ZIP archive).")
    parser.add_argument(
        "--analysis-mode",
        choices=["dynamic", "static"],
        default="dynamic",
        help="dynamic: execute in a sandbox; static: disassemble only.",
    )
    parser.add_argument("--label", default="", help="Label to attach to the submission.")
    parser.add_argument(
        "--disable-network", action="store_true", help="Disable network access in the sandbox VM (dynamic only)."
    )
    parser.add_argument("--timeout", type=int, default=180, help="Seconds the sample is allowed to run (dynamic only).")
    parser.add_argument("--environments", nargs="+", help="Sandbox VMs to run in (e.g. win10_latest_x64).")
    parser.add_argument("--priority", default="normal", choices=["low", "normal", "high"], help="Submission priority.")
    parser.add_argument("--wait", action="store_true", help="Wait for the analysis to complete and show the report.")
    parser.add_argument(
        "--wait-timeout", type=int, default=1800, help="Max seconds to wait when --wait is given (default: 1800)."
    )

    raw = parser.add_argument_group("static analysis (raw binary options)")
    raw.add_argument("--raw-binary-file-format", choices=["unknown", "raw", "pe"])
    raw.add_argument("--raw-binary-cpu-architecture", choices=["x86-32", "x86-64"])
    raw.add_argument("--raw-binary-image-base-address", type=parse_address, help="Decimal or hex, e.g. 0x400000.")
    raw.add_argument(
        "--raw-binary-function-entry-point-detection-needed",
        type=lambda s: s.lower() in ("1", "true", "yes"),
        help="true / false.",
    )
    raw.add_argument("--raw-binary-function-file-offset", type=parse_address, help="Decimal or hex, e.g. 0x1000.")

    args = parser.parse_args()
    try:
        submit_sample(args)
    except ConfigError as e:
        raise SystemExit(f"error: {e}")
