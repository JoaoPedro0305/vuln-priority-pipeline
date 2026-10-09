import hashlib

import pytest
import requests
import responses

from vulnprio.config import USER_AGENT
from vulnprio.download import DownloadError, NotPublishedError, download, make_session

URL = "https://example.test/data.json"


@responses.activate
def test_download_saves_the_file_and_its_fingerprint(tmp_path):
    body = b'{"ok": true}'
    responses.get(URL, body=body)

    result = download(make_session(), URL, tmp_path / "sub" / "data.json")

    assert result.path.read_bytes() == body
    assert result.sha256 == hashlib.sha256(body).hexdigest()
    assert result.size == len(body)
    assert result.url == URL
    assert responses.calls[0].request.headers["User-Agent"] == USER_AGENT


@responses.activate
def test_not_found_codes_raise_not_published(tmp_path):
    responses.get(URL, status=403)

    with pytest.raises(NotPublishedError, match="HTTP 403"):
        download(make_session(), URL, tmp_path / "data.json", not_found=(403, 404))
    assert list(tmp_path.iterdir()) == []


@responses.activate
def test_server_error_raises_and_keeps_the_previous_file(tmp_path):
    dest = tmp_path / "data.json"
    dest.write_bytes(b"yesterday")
    responses.get(URL, status=500)

    with pytest.raises(requests.HTTPError):
        download(make_session(), URL, dest)
    assert dest.read_bytes() == b"yesterday"
    assert not (tmp_path / "data.json.part").exists()


@responses.activate
def test_size_limit_stops_the_download(tmp_path):
    responses.get(URL, body=b"x" * 1000)

    with pytest.raises(DownloadError, match="larger than"):
        download(make_session(), URL, tmp_path / "data.json", max_bytes=100)
    assert list(tmp_path.iterdir()) == []


def test_plain_http_is_refused(tmp_path):
    with pytest.raises(DownloadError, match="non-HTTPS"):
        download(make_session(), "http://example.test/data.json", tmp_path / "data.json")


def test_session_retries_rate_limits_and_server_errors():
    retry = make_session().get_adapter(URL).max_retries
    assert retry.total == 5
    assert {429, 500, 502, 503, 504} <= set(retry.status_forcelist)
    assert retry.respect_retry_after_header
