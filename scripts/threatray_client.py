"""Thin HTTP client used by the example scripts.

Configuration is read from environment variables:

- ``THREATRAY_API_KEY`` — required.
- ``THREATRAY_API_URL`` — base URL for on-prem / self-hosted deployments
  (e.g. ``https://threatray.acme.internal``). Takes precedence if both are set.
- ``THREATRAY_REALM`` — SaaS realm (e.g. ``acme``), expands to
  ``https://api-{realm}.analysis.threatray.com``.
"""

import os
from dataclasses import dataclass
from typing import Any

import requests

# Default timeouts (seconds). Sample uploads can exceed 30s, so POST is more
# generous than GET. Streaming downloads use a (connect, read) pair.
DEFAULT_GET_TIMEOUT = 30.0
DEFAULT_POST_TIMEOUT = 300.0
DEFAULT_STREAM_TIMEOUT = (10.0, 60.0)


class ConfigError(RuntimeError):
    """Raised when required environment configuration is missing or invalid."""


@dataclass
class Client:
    api_key: str
    api_url: str

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.api_url}{path}"

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Apikey {self.api_key}"}

    def get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        timeout: float = DEFAULT_GET_TIMEOUT,
    ) -> requests.Response:
        return requests.get(self.url(path), params=params, headers=self.headers(), timeout=timeout)

    def post(
        self,
        path: str,
        *,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        timeout: float = DEFAULT_POST_TIMEOUT,
    ) -> requests.Response:
        return requests.post(self.url(path), data=data, files=files, headers=self.headers(), timeout=timeout)

    def stream_get(
        self,
        path: str,
        *,
        timeout: tuple[float, float] = DEFAULT_STREAM_TIMEOUT,
    ) -> requests.Response:
        return requests.get(self.url(path), headers=self.headers(), stream=True, timeout=timeout)


_client: Client | None = None


def get_client() -> Client:
    """Return the configured client, building one from env vars on first call."""
    global _client
    if _client is not None:
        return _client

    api_key = os.environ.get("THREATRAY_API_KEY")
    api_url = os.environ.get("THREATRAY_API_URL")
    realm = os.environ.get("THREATRAY_REALM")

    if not api_key:
        raise ConfigError("THREATRAY_API_KEY is not set.")

    if api_url:
        resolved_url = api_url.rstrip("/")
    elif realm:
        resolved_url = f"https://api-{realm}.analysis.threatray.com"
    else:
        raise ConfigError("set THREATRAY_API_URL (on-prem) or THREATRAY_REALM (SaaS).")

    _client = Client(api_key=api_key, api_url=resolved_url)
    return _client
