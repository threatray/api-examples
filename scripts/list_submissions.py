import argparse
from datetime import datetime, timezone
from typing import Any

from threatray_client import ConfigError, get_client


def get_submissions() -> dict[str, Any]:
    client = get_client()
    resp = client.get("/v1/submissions")
    if resp.status_code != 200:
        print(f"Failed to get the submissions: [{resp.status_code}] {resp.text}")
        return {}
    return resp.json()


def display_submissions(limit: int) -> None:
    submissions = get_submissions().get("submissions", [])[:limit]

    header = ("User", "Created at", "Analysis ID", "File name", "SHA256", "Verdict", "Threats", "Status")
    rows: list[tuple[str, ...]] = [header]
    for s in submissions:
        try:
            rows.append(
                (
                    s["username"],
                    str(datetime.fromtimestamp(s["created_at"], tz=timezone.utc)),
                    s["analysis"]["id"],
                    s["sample"]["file_name"],
                    s["sample"]["hash_sha256"],
                    s["analysis"]["verdict"],
                    ",".join(t["label"] for t in s["analysis"]["threats"]),
                    s["status"],
                )
            )
        except KeyError:
            continue

    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    for i, row in enumerate(rows):
        print("  ".join(cell.ljust(widths[j]) for j, cell in enumerate(row)))
        if i == 0:
            print("  ".join("-" * w for w in widths))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="List recent submissions.")
    parser.add_argument("--limit", type=int, default=10, help="Max submissions to show (default: 10).")
    args = parser.parse_args()

    try:
        display_submissions(args.limit)
    except ConfigError as e:
        raise SystemExit(f"error: {e}")
