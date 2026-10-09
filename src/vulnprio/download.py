"""HTTP downloads shared by every source.

- Retries 429 and 5xx answers with exponential backoff, honouring Retry-After.
- Streams to a ".part" file and renames it only when complete, so a failed
  download never leaves a truncated file that looks valid.
- Stops at a size limit, so a misbehaving server cannot fill the disk.
- Returns the SHA-256 of the saved file, recorded in the load log.
"""

import hashlib
import logging
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


class DownloadError(Exception):
    pass


class NotPublishedError(DownloadError):
    """The file does not exist on the server (e.g. a day not published yet)."""


@dataclass(frozen=True)
class Downloaded:
    path: Path
    url: str  # final URL, after redirects
    sha256: str
    size: int


def make_session(retries: int = 5) -> requests.Session:
    retry = Retry(
        total=retries,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
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
) -> Downloaded:
    """Save `url` to `dest`. Status codes in `not_found` raise NotPublishedError."""
    if not url.startswith("https://"):
        raise DownloadError(f"refusing a non-HTTPS URL: {url}")

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

            with part.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=CHUNK):
                    size += len(chunk)
                    if size > max_bytes:
                        raise DownloadError(f"{url} is larger than {max_bytes} bytes")
                    digest.update(chunk)
                    fh.write(chunk)
            final_url = response.url
    except BaseException:
        part.unlink(missing_ok=True)
        raise

    part.replace(dest)
    log.info("downloaded %s (%d bytes)", final_url, size)
    return Downloaded(path=dest, url=final_url, sha256=digest.hexdigest(), size=size)
