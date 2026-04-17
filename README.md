# Threatray API Examples

Example Python scripts for the [Threatray](https://www.threatray.com) REST API. Use them to submit
samples for analysis, fetch reports, run search / retrohunt queries, and download samples.

Depends only on `requests` — there is no Threatray SDK to install. The scripts are small (~100
lines each) and meant to be read, copied, and adapted.

API reference: https://docs.threatray.com/reference.

## Requirements

- Python 3.10+
- A Threatray API key (UI → *Settings → API keys*)

## Setup

With [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv sync
```

With plain `pip`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Authentication

All scripts read configuration from environment variables:

| Env var               | Purpose                                                              |
| --------------------- | -------------------------------------------------------------------- |
| `THREATRAY_API_KEY`   | Your API key. Required.                                              |
| `THREATRAY_REALM`     | SaaS realm (e.g. `acme` → `https://api-acme.analysis.threatray.com`). |
| `THREATRAY_API_URL`   | Base URL for on-prem / self-hosted deployments. Do not include `/v1`. |

Set either `THREATRAY_REALM` (SaaS) or `THREATRAY_API_URL` (on-prem). If both are set, `THREATRAY_API_URL` wins.

### SaaS

```bash
export THREATRAY_API_KEY="..."
export THREATRAY_REALM="acme"
uv run scripts/list_submissions.py
```

### On-prem

```bash
export THREATRAY_API_KEY="..."
export THREATRAY_API_URL="https://threatray.acme.internal"
uv run scripts/list_submissions.py
```

## Scripts

| Script                    | Endpoint(s)                                                     | What it does                                  |
| ------------------------- | --------------------------------------------------------------- | --------------------------------------------- |
| `submit_sample.py`        | `POST /v1/submissions/samples`                                  | Submit a file for dynamic or static analysis. |
| `list_submissions.py`     | `GET /v1/submissions`                                           | List recent submissions.                      |
| `get_report.py`           | `GET /v1/samples/{hash}`, `/v1/analyses/{id}`                   | Fetch the report of a sample or analysis.     |
| `search.py`               | `GET /v1/search`                                                | Search / retrohunt by IOC, YARA, hash, etc.   |
| `download_file.py`        | `GET /v1/files/{hash}/data`                                     | Download a sample by hash.                    |

See [`scripts/README.md`](scripts/README.md) for example invocations.

## Calling the API directly

If you only need the two primitives (base URL + auth header):

```python
import requests

headers = {"Authorization": f"Apikey {api_key}"}
base_url = "https://api-<your-realm>.analysis.threatray.com"   # or your on-prem URL

r = requests.get(f"{base_url}/v1/submissions", headers=headers)
r.raise_for_status()
print(r.json())
```

## License

MIT — see [LICENSE](LICENSE).
