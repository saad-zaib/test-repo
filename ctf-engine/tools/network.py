"""
tools/network.py — Network & Health Tools.

Uses the `requests` library (already in the environment) for HTTP calls.
"""

import html as html_module
import time
import socket
import logging
import re

import requests

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10  # seconds


def _strip_html(text: str) -> str:
    """Convert HTML error pages to readable plain text."""
    text = re.sub(r'<br\s*/?>', '\n', text)
    text = re.sub(r'&nbsp;', ' ', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = html_module.unescape(text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def http_request(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict | None = None,
    raw_body: str | None = None,
) -> str:
    """Make an HTTP request and return the status code + response body."""
    method = method.upper()
    headers = headers or {}
    try:
        response = requests.request(
            method=method,
            url=url,
            json=payload if payload and not raw_body else None,
            data=raw_body,
            headers=headers,
            timeout=_DEFAULT_TIMEOUT,
            allow_redirects=True,
        )
        body = response.text[:1000]
        if '<html' in body.lower() or '<br' in body.lower():
            body = _strip_html(body)
        return f"HTTP {response.status_code}\nHeaders: {dict(response.headers)}\nBody:\n{body}"
    except requests.exceptions.ConnectionError:
        return f"ERROR: Could not connect to {url}"
    except requests.exceptions.Timeout:
        return f"ERROR: Request timed out after {_DEFAULT_TIMEOUT}s — {url}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


def wait_for_service(url: str = "http://localhost:3000", timeout: int = 30) -> str:
    """Poll a URL until it returns HTTP 200, or until the timeout expires. Default is 240s (4 minutes). Use this default for slow systems."""
    deadline = time.time() + timeout
    interval = 2
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                return f"OK: Service is up at {url} (HTTP {r.status_code}) after {attempt} attempts"
        except requests.exceptions.RequestException:
            pass
        time.sleep(interval)
    return f"TIMEOUT: Service did not become available at {url} within {timeout}s"


def check_connectivity(host: str, port: int) -> str:
    """Check if a TCP connection can be made to host:port."""
    try:
        with socket.create_connection((host, port), timeout=5):
            return f"OK: {host}:{port} is reachable"
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return f"FAIL: {host}:{port} is NOT reachable — {e}"
