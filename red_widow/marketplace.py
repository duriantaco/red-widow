from __future__ import annotations

import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


VSCODE_MARKETPLACE_QUERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
OPENVSX_API_BASE_URL = "https://open-vsx.org/api"
DEFAULT_MARKETPLACE_SOURCES = ("vscode", "openvsx")
VSCODE_ALLOWED_HOSTS = ("marketplace.visualstudio.com",)
OPENVSX_ALLOWED_HOSTS = ("open-vsx.org",)


@dataclass(frozen=True)
class MarketplacePackage:
    extension_id: str
    source: str
    version: str
    download_url: str
    path: str
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "extensionId": self.extension_id,
            "source": self.source,
            "version": self.version,
            "downloadUrl": self.download_url,
            "path": self.path,
            "cached": self.cached,
        }


@dataclass(frozen=True)
class MarketplaceError:
    extension_id: str
    source: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "extensionId": self.extension_id,
            "source": self.source,
            "error": self.error,
        }


@dataclass(frozen=True)
class _MarketplaceMetadata:
    extension_id: str
    source: str
    version: str
    download_url: str


def resolve_marketplace_recommendations(
    extension_ids: Iterable[str],
    cache_dir: str | Path,
    timeout: int = 20,
    sources: tuple[str, ...] = DEFAULT_MARKETPLACE_SOURCES,
) -> tuple[list[MarketplacePackage], list[MarketplaceError]]:
    packages: list[MarketplacePackage] = []
    errors: list[MarketplaceError] = []

    for extension_id in sorted({item.lower() for item in extension_ids if item}):
        try:
            publisher, name = _split_extension_id(extension_id)
        except ValueError as exc:
            errors.append(MarketplaceError(extension_id, "marketplace", str(exc)))
            continue

        source_errors: list[MarketplaceError] = []
        for source in sources:
            try:
                metadata = _metadata_for_source(source, publisher, name, timeout)
                package = _cached_or_downloaded_package(metadata, Path(cache_dir), timeout)
            except (OSError, ValueError, urllib.error.URLError) as exc:
                source_errors.append(MarketplaceError(extension_id, source, str(exc)))
                continue
            packages.append(package)
            source_errors = []
            break
        errors.extend(source_errors)

    return packages, errors


def _metadata_for_source(
    source: str,
    publisher: str,
    name: str,
    timeout: int,
) -> _MarketplaceMetadata:
    if source == "vscode":
        return _vscode_metadata(publisher, name, timeout)
    if source == "openvsx":
        return _openvsx_metadata(publisher, name, timeout)
    raise ValueError(f"unsupported marketplace source: {source}")


def _vscode_metadata(publisher: str, name: str, timeout: int) -> _MarketplaceMetadata:
    extension_id = f"{publisher}.{name}"
    query_url = os.environ.get("RED_WIDOW_VSCODE_MARKETPLACE_QUERY_URL", VSCODE_MARKETPLACE_QUERY_URL)
    _validate_marketplace_url(query_url, VSCODE_ALLOWED_HOSTS)
    payload = {
        "filters": [
            {
                "criteria": [{"filterType": 7, "value": extension_id}],
                "pageNumber": 1,
                "pageSize": 1,
                "sortBy": 0,
                "sortOrder": 0,
            }
        ],
        "assetTypes": [],
        "flags": 914,
    }
    response = _http_json(
        query_url,
        timeout=timeout,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/json;api-version=3.0-preview.1",
            "Content-Type": "application/json",
        },
    )
    extensions = response.get("results", [{}])[0].get("extensions", [])
    if not isinstance(extensions, list) or not extensions:
        raise ValueError(f"{extension_id} was not found in VS Code Marketplace")
    extension = extensions[0]
    versions = extension.get("versions", [])
    if not isinstance(versions, list) or not versions:
        raise ValueError(f"{extension_id} has no downloadable versions in VS Code Marketplace")
    version = str(versions[0].get("version", ""))
    if not version:
        raise ValueError(f"{extension_id} metadata did not include a version")

    base = os.environ.get(
        "RED_WIDOW_VSCODE_MARKETPLACE_DOWNLOAD_BASE",
        "https://marketplace.visualstudio.com/_apis/public/gallery",
    ).rstrip("/")
    _validate_marketplace_url(base, VSCODE_ALLOWED_HOSTS)
    quoted_publisher = urllib.parse.quote(publisher, safe="")
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    download_url = (
        f"{base}/publishers/{quoted_publisher}/vsextensions/{quoted_name}/"
        f"{quoted_version}/vspackage"
    )
    return _MarketplaceMetadata(extension_id, "vscode", version, download_url)


def _openvsx_metadata(publisher: str, name: str, timeout: int) -> _MarketplaceMetadata:
    extension_id = f"{publisher}.{name}"
    base_url = os.environ.get("RED_WIDOW_OPENVSX_API_BASE_URL", OPENVSX_API_BASE_URL).rstrip("/")
    _validate_marketplace_url(base_url, OPENVSX_ALLOWED_HOSTS)
    url = (
        f"{base_url}/{urllib.parse.quote(publisher, safe='')}/"
        f"{urllib.parse.quote(name, safe='')}/latest"
    )
    response = _http_json(url, timeout=timeout, headers={"Accept": "application/json"})
    version = str(response.get("version", ""))
    files = response.get("files", {})
    download_url = files.get("download") if isinstance(files, dict) else ""
    if not version or not isinstance(download_url, str) or not download_url:
        raise ValueError(f"{extension_id} metadata did not include a downloadable VSIX")
    resolved_download_url = urllib.parse.urljoin(base_url + "/", download_url)
    _validate_marketplace_url(resolved_download_url, OPENVSX_ALLOWED_HOSTS)
    return _MarketplaceMetadata(
        extension_id=extension_id,
        source="openvsx",
        version=version,
        download_url=resolved_download_url,
    )


def _cached_or_downloaded_package(
    metadata: _MarketplaceMetadata,
    cache_dir: Path,
    timeout: int,
) -> MarketplacePackage:
    package_path = _cache_path(cache_dir, metadata)
    if package_path.is_file():
        return MarketplacePackage(
            extension_id=metadata.extension_id,
            source=metadata.source,
            version=metadata.version,
            download_url=metadata.download_url,
            path=str(package_path),
            cached=True,
        )

    package_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=package_path.name + ".",
        suffix=".tmp",
        dir=str(package_path.parent),
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        _download_file(metadata.download_url, temp_path, timeout)
        temp_path.replace(package_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()

    return MarketplacePackage(
        extension_id=metadata.extension_id,
        source=metadata.source,
        version=metadata.version,
        download_url=metadata.download_url,
        path=str(package_path),
        cached=False,
    )


def _cache_path(cache_dir: Path, metadata: _MarketplaceMetadata) -> Path:
    safe_id = metadata.extension_id.replace("/", "_")
    safe_version = metadata.version.replace("/", "_")
    return cache_dir / metadata.source / safe_id / f"{safe_id}-{safe_version}.vsix"


def _http_json(
    url: str,
    timeout: int,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    _validate_known_marketplace_url(url)
    request = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{url}: response was not a JSON object")
    return payload


def _download_file(url: str, path: Path, timeout: int) -> None:
    _validate_known_marketplace_url(url)
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=timeout) as response, path.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)


def _split_extension_id(extension_id: str) -> tuple[str, str]:
    parts = extension_id.split(".", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"extension ID must look like publisher.name: {extension_id}")
    return parts[0], parts[1]


def _validate_known_marketplace_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if _host_matches(host, VSCODE_ALLOWED_HOSTS):
        _validate_marketplace_url(url, VSCODE_ALLOWED_HOSTS)
        return
    if _host_matches(host, OPENVSX_ALLOWED_HOSTS):
        _validate_marketplace_url(url, OPENVSX_ALLOWED_HOSTS)
        return
    raise ValueError(f"marketplace URL host is not allowed: {host or '<missing>'}")


def _validate_marketplace_url(url: str, allowed_hosts: tuple[str, ...]) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"marketplace URL must use https: {url}")
    if parsed.username or parsed.password:
        raise ValueError("marketplace URL must not include credentials")
    host = (parsed.hostname or "").lower()
    if not _host_matches(host, allowed_hosts):
        raise ValueError(f"marketplace URL host is not allowed: {host or '<missing>'}")


def _host_matches(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)
