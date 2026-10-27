"""HTTP client for Brother firmverup.brother.co.jp endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from .protocol import (
    FileUpdateParams,
    VerCheckParams,
    build_file_update_request,
    build_ver_check_request,
    parse_response_xml,
    summarize_file_update,
    summarize_ver_check,
)


@dataclass(frozen=True)
class FirmverupUrls:
    """From BrUpdSys.xml <Servlet>."""

    ver_check: str = (
        "https://firmverup.brother.co.jp/kne_bh7_update_nt_ssl/ifax2.asmx/verCheck"
    )
    file_update: str = (
        "https://firmverup.brother.co.jp/kne_bh7_update_nt_ssl/ifax2.asmx/fileUpdate"
    )


class FirmverupClient:
    def __init__(
        self,
        urls: FirmverupUrls | None = None,
        timeout: float = 60.0,
        session: requests.Session | None = None,
    ) -> None:
        self.urls = urls or FirmverupUrls()
        self.timeout = timeout
        self.session = session or requests.Session()
        # BrHttpc/1.00 matches printer/EWS sniffed requests that return PATH.
        self.session.headers.setdefault("User-Agent", "BrHttpc/1.00")
        self.session.headers.setdefault("Content-Type", "text/xml")

    def _post(self, url: str, body: str) -> requests.Response:
        return self.session.post(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "text/xml", "User-Agent": "BrHttpc/1.00"},
            timeout=self.timeout,
        )

    def download_path(self, path_url: str, dest: Path) -> Path:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self.session.get(path_url, stream=True, timeout=self.timeout) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(256 * 1024):
                    if chunk:
                        f.write(chunk)
        return dest

    def ver_check(self, params: VerCheckParams | None = None) -> dict[str, Any]:
        body = build_ver_check_request(params)
        resp = self._post(self.urls.ver_check, body)
        resp.raise_for_status()
        root = parse_response_xml(resp.content)
        return {
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type"),
            "request_xml": body,
            "raw": resp.content,
            "summary": summarize_ver_check(root),
        }

    def file_update(self, params: FileUpdateParams | None = None) -> dict[str, Any]:
        body = build_file_update_request(params)
        resp = self._post(self.urls.file_update, body)
        resp.raise_for_status()
        ct = (resp.headers.get("Content-Type") or "").lower()
        result: dict[str, Any] = {
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type"),
            "request_xml": body,
            "raw": resp.content,
            "byte_length": len(resp.content),
        }
        if "xml" in ct or (resp.content[:1] == b"<"):
            root = parse_response_xml(resp.content)
            result["summary"] = summarize_file_update(root)
            result["kind"] = "xml"
        else:
            result["kind"] = "binary"
            result["summary"] = None
        return result

    def save_raw(self, result: dict[str, Any], path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(result["raw"])
        return path
