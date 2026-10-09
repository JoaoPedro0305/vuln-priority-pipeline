"""HTTP downloads shared by every source.

- Retries 429 and 5xx answers with exponential backoff, honouring Retry-After.
- Streams to a ".part" file and renames it only when complete, so a failed
  download never leaves a truncated file that looks valid.
- Stops at a size limit, so a misbehaving server cannot fill the disk.
- Abandons a connection that slows to a trickle and starts over: a few bytes
  per second never trigger the read timeout, but can stretch a download that
  normally takes seconds into many minutes (seen with the NVD feeds).
- Returns the SHA-256 of the saved file, recorded in the load log.
"""

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from vulnprio.config import USER_AGENT

log = logging.getLogger(__name__)

TIMEOUT = (10, 120)  # seconds to connect, seconds between bytes
MAX_BYTES = 500 * 1024 * 1024
CHUNK = 64 * 1024
MIN_SPEED = 50 * 1024  # bytes per second, measured over each SPEED_WINDOW
SPEED_WINDOW = 30.0  # seconds
ATTEMPTS = 3  # for transfers that stall or break midway (urllib3 only retries before the body)
RETRY_PAUSE = 5.0  # seconds


class DownloadError(Exception):
    pass


class StalledDownloadError(DownloadError):
    """The transfer went on, but slower than MIN_SPEED."""


class NotPublishedError(DownloadError):
    """The file does not exist on the server (e.g. a day not published yet)."""


@dataclass(frozen=True)
class Downloaded:
    path: Path
    url: str  # final URL, after redirects
    sha256: str
    size: int


def make_session(retries: int = 5, extra_retry_statuses: tuple[int, ...] = ()) -> requests.Session:
    retry = Retry(
        total=retries,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504, *extra_retry_statuses),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        raise_on_status=False,  # after the last retry, raise_for_status() reports it
    )
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def download(
    session: requests.Session,
    url: str,
    dest: Path,
    *,
    not_found: tuple[int, ...] = (404,),
    max_bytes: int = MAX_BYTES,
    min_speed: float = MIN_SPEED,
    attempts: int = ATTEMPTS,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Downloaded:
    """Save `url` to `dest`. Status codes in `not_found` raise NotPublishedError.

    A transfer that stalls or breaks midway is started again, up to `attempts` times.
    """
    if not url.startswith("https://"):
        raise DownloadError(f"refusing a non-HTTPS URL: {url}")

    for attempt in range(1, attempts + 1):
        try:
            return _download_once(session, url, dest, not_found, max_bytes, min_speed, clock)
        except (StalledDownloadError, requests.ConnectionError, requests.exceptions.ChunkedEncodingError) as err:
            if attempt == attempts:
                raise
            log.warning("%s: %s; starting again (attempt %d of %d)", url, err, attempt + 1, attempts)
            sleep(RETRY_PAUSE)
    raise AssertionError("unreachable")  # pragma: no cover


def _download_once(
    session: requests.Session,
    url: str,
    dest: Path,
    not_found: tuple[int, ...],
    max_bytes: int,
    min_speed: float,
    clock: Callable[[], float],
) -> Downloaded:
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    size = 0

    try:
        with session.get(url, stream=True, timeout=TIMEOUT) as response:
            if response.status_code in not_found:
                raise NotPublishedError(f"{url} is not available (HTTP {response.status_code})")
            response.raise_for_status()
            if not response.url.startswith("https://"):
                raise DownloadError(f"redirected to a non-HTTPS URL: {response.url}")

            window_start, window_bytes = clock(), 0
            with part.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=CHUNK):
                    size += len(chunk)
                    if size > max_bytes:
                        raise DownloadError(f"{url} is larger than {max_bytes} bytes")
                    digest.update(chunk)
                    fh.write(chunk)

                    window_bytes += len(chunk)
                    elapsed = clock() - window_start
                    if elapsed >= SPEED_WINDOW:
                        speed = window_bytes / elapsed
                        if speed < min_speed:
                            raise StalledDownloadError(f"only {speed / 1024:.0f} KB/s over the last {elapsed:.0f} s")
                        window_start, window_bytes = clock(), 0
            final_url = response.url
    except BaseException:
        part.unlink(missing_ok=True)
        raise

    part.replace(dest)
    log.info("downloaded %s (%d bytes)", final_url, size)
    return Downloaded(path=dest, url=final_url, sha256=digest.hexdigest(), size=size)
