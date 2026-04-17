import argparse

from threatray_client import ConfigError, get_client

SELECTORS = {
    "domain": "Search by domain IOCs.",
    "ip": "Search by IP IOCs.",
    "url": "Search by URL IOCs.",
    "mutex": "Search by mutex IOCs.",
    "registry": "Search by registry IOCs.",
    "file": "Search by file IOCs.",
    "retrohunt": "Retrohunt by hash.",
    "process": "Search by process and command line.",
    "signature": "Search by threat signature name.",
    "label": "Search by analysis label.",
    "yara": "Search by YARA rule name.",
    "verdict": "Search by verdict (malicious, suspicious, unknown).",
    "sample-name": "Search by submitted file name.",
    "analysis-id": "Search by analysis ID.",
    "file-hash": "Search by file hash (MD5, SHA1, SHA256).",
    "memory-hash": "Search by memory region hash (MD5, SHA1, SHA256).",
}


def sanitize_value(value: str) -> str:
    if not value:
        return value
    value = value.strip('"')
    value = value.replace('"', '\\"')
    return value


def build_query(args: argparse.Namespace) -> str:
    args_dict = vars(args)
    parts: list[str] = []
    for name in SELECTORS:
        raw = args_dict.get(name.replace("-", "_"))
        if raw:
            parts.append(f'{name}: "{sanitize_value(raw)}"')
    return " ".join(parts)


def search(query: str, scope: str, max_results: int) -> None:
    client = get_client()
    print(f"Query: {query}")
    resp = client.get(
        "/v1/search",
        params={"query": query, "scope": scope, "max_results": max_results},
    )
    if resp.status_code != 200:
        try:
            body = resp.json()
            msg = body.get("description") or body.get("title") or resp.text
        except ValueError:
            msg = resp.text
        print(f"Failed to search [{resp.status_code}]: {msg}")
        return

    data = resp.json()
    analyses = data.get("analyses") or []
    print(f"Found {len(analyses)} matching analyses.")

    threats = (data.get("aggregations") or {}).get("threats") or []
    if threats:
        print("Threats:")
        for threat in threats:
            print(f"  {threat['key']}: {threat['count']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for samples by IOCs. Multiple selectors are ANDed together.")
    for name, help_text in SELECTORS.items():
        parser.add_argument(f"--{name}", type=str, help=help_text)
    parser.add_argument(
        "--scope", default="both", choices=["both", "private", "public"], help="Limit search to a scope."
    )
    parser.add_argument("--max-results", type=int, default=250, help="Max analyses to return (API max: 2500).")

    args = parser.parse_args()
    query = build_query(args)
    if not query:
        parser.error("No selector given (e.g. --domain, --yara, --file-hash, ...).")

    try:
        search(query, args.scope, args.max_results)
    except ConfigError as e:
        raise SystemExit(f"error: {e}")
