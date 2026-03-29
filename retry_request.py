"""
retry_request.py — Shared HTTP retry logic with exponential backoff + jitter.

Used by ppq_provision.py and create_vm.py to survive transient API outages
(LNVPS and PPQ both go down regularly). Designed for provisioning flows where
a customer is waiting — keeps retrying for up to 15 minutes with short,
capped intervals so they see progress.

Behavior:
  - Retries on: HTTP 5xx, connection errors, timeouts
  - Does NOT retry on: 4xx (client errors, auth failures)
  - Backoff: 3s → 6s → 12s → 24s → 30s (capped), with ±50% random jitter
  - Total retry window: 15 minutes by default
  - Raises RetryExhaustedError on exhaustion (never returns None silently)
"""

import random
import time

import requests


# Defaults — callers can override per-call
DEFAULT_TIMEOUT_SEC = 900       # 15 minutes total retry window
DEFAULT_INITIAL_BACKOFF = 3     # seconds before first retry
DEFAULT_MAX_BACKOFF = 30        # cap on wait between retries
DEFAULT_REQUEST_TIMEOUT = 30    # per-request HTTP timeout


class RetryExhaustedError(Exception):
    """All retries exhausted for an API request."""

    def __init__(self, message, last_status=None, last_body=None):
        super().__init__(message)
        self.last_status = last_status
        self.last_body = last_body


def retry_request(
    method,
    url,
    *,
    timeout_sec=DEFAULT_TIMEOUT_SEC,
    initial_backoff=DEFAULT_INITIAL_BACKOFF,
    max_backoff=DEFAULT_MAX_BACKOFF,
    request_timeout=DEFAULT_REQUEST_TIMEOUT,
    prepare_headers=None,
    label=None,
    log_fn=None,
    **kwargs,
):
    """Make an HTTP request with exponential backoff + jitter on transient errors.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL to request
        timeout_sec: Total wall-clock time to keep retrying (default 15 min)
        initial_backoff: Seconds before first retry (default 3)
        max_backoff: Cap on wait between retries (default 30)
        request_timeout: Per-request HTTP timeout (default 30)
        prepare_headers: Optional callback() -> dict of headers. Called on EACH
                         attempt, so auth tokens (like NIP-98) get fresh timestamps.
                         Merged into kwargs["headers"].
        label: Human-readable label for log messages (e.g. "PPQ", "LNVPS POST /api/v1/vm")
        log_fn: Callable for log messages (default: print). Signature: log_fn(msg).
        **kwargs: Passed through to requests.request() (headers, json, data, etc.)

    Returns:
        requests.Response on success (status < 500)

    Raises:
        RetryExhaustedError: All retries exhausted (API still down after timeout_sec)
    """
    if log_fn is None:
        log_fn = lambda msg: print(f"  {msg}")
    if label is None:
        label = f"{method} {url}"

    kwargs.setdefault("timeout", request_timeout)
    deadline = time.time() + timeout_sec
    attempt = 0
    backoff = initial_backoff
    last_status = None
    last_body = None

    while True:
        attempt += 1
        remaining = max(0, int(deadline - time.time()))

        # Merge fresh headers on each attempt (for NIP-98 re-signing etc.)
        if prepare_headers is not None:
            fresh = prepare_headers()
            merged = dict(kwargs.get("headers") or {})
            merged.update(fresh)
            kwargs["headers"] = merged

        try:
            resp = requests.request(method, url, **kwargs)
            if resp.status_code < 500:
                return resp

            # Server error — retry if we have time
            last_status = resp.status_code
            last_body = resp.text[:300]
            if time.time() >= deadline:
                break

            wait = _jittered_backoff(backoff, max_backoff)
            log_fn(f"{label} → HTTP {resp.status_code}, retrying in {wait:.0f}s "
                   f"(attempt {attempt}, {remaining}s remaining)")
            time.sleep(wait)
            backoff = min(backoff * 2, max_backoff)

        except (requests.ConnectionError, requests.Timeout) as exc:
            last_status = None
            last_body = f"{type(exc).__name__}: {exc}"
            if time.time() >= deadline:
                break

            wait = _jittered_backoff(backoff, max_backoff)
            log_fn(f"{label} → {type(exc).__name__}, retrying in {wait:.0f}s "
                   f"(attempt {attempt}, {remaining}s remaining)")
            time.sleep(wait)
            backoff = min(backoff * 2, max_backoff)

    # Exhausted
    msg = (f"{label} failed after {attempt} attempts over {timeout_sec}s"
           f" (last: HTTP {last_status})" if last_status else
           f"{label} failed after {attempt} attempts over {timeout_sec}s"
           f" (last: {last_body})")
    raise RetryExhaustedError(msg, last_status=last_status, last_body=last_body)


def _jittered_backoff(backoff, max_backoff):
    """Exponential backoff with ±50% random jitter, capped at max_backoff."""
    jittered = backoff * random.uniform(0.5, 1.5)
    return min(jittered, max_backoff)
