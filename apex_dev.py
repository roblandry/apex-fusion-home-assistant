#!/usr/bin/env python3
"""Apex (Neptune) dev helper.

This script is intentionally Apex-only (no ReefBeat logic).

Commands:
  - scan: LAN-scan one or more CIDRs for Apex controllers
  - dump: dump raw payloads from one or more Apex controllers

Credentials:
  - CLI flags --username/--password
  - Or environment variables APEX_USERNAME/APEX_PASSWORD
    - Or a .env file containing APEX_USERNAME/APEX_PASSWORD (auto-detected)

IPs list:
    - CLI --ip (repeatable)
    - Or env var APEX_IPS='10.0.30.40,10.0.30.41'
    - Back-compat: APEX_DEVICES supports the older name@host format

Optional extra endpoints:
    - Env var APEX_EXTRA_ENDPOINTS='/cgi-bin/status.cgi,/rest/status'

Dump output:
    .dev/dumps/<device>/<YYYYmmdd-HHMMSS>/
        <endpoint>/data   (pretty JSON if JSON; pretty XML if XML; otherwise raw/text)
        _root/data        (used for '/', to avoid clobbering device.json/summary.json)

Redaction:
    - Dump output is redacted by default to avoid leaking secrets.
    - Set APEX_REDACT=0 to disable redaction.

Detection strategy:
  - Legacy Apex: /cgi-bin/status.xml (often Basic Auth protected)
  - Newer Apex:  /rest/login + /rest/status + /rest/config (cookie session)

Note: Scanning a /24 can be noisy; start with your home subnet.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPCookieProcessor, OpenerDirector, Request, build_opener
from xml.dom import minidom
from xml.parsers.expat import ExpatError

LOG = logging.getLogger("apex_dev")

# Base endpoints to dump. Anything requiring IDs should be discovered dynamically.
#
# NOTE: Keep iterated endpoints (like feeds) in constants below and expand them
# programmatically so we don't hardcode the same pattern N times.
REST_BASE_ENDPOINTS: list[str] = [
    "rest/config",
    "rest/config/cal",  # Calibrations Performed?
    "rest/config/clock",  # Clock Config
    "rest/config/dconf",  # Device Config
    "rest/config/iconf",  # Input Config
    "rest/config/mconf",  # Modules Config
    "rest/config/misc",  # Misc Config
    "rest/config/nconf",  # Network Config
    "rest/config/oconf",  # Output Config
    "rest/config/pconf",  # Profiles Config
    "rest/config/season",  # Seasons Config
    "rest/dlog",  # Device Log
    "rest/olog",  # Input Log
    "rest/olog",  # Output Log
    "rest/status",
    "rest/status/inputs",  # Input Status, individual endpoints seem same as base ?
    # "rest/status/modules",  # Module Status, only ever returns {}
    # "rest/status/nstat",  # 401 response
    "rest/status/outputs",  # Output Status, individual endpoints seem same as base ?
    # "rest/status/power",  # 401 response
    # "rest/status/system",  # 401 response
    "rest/tlog",
    "rest/user",
    "rest/wifi",
]


# Iterated REST endpoints (expand into concrete endpoints).
REST_FEED_INDEXES: range = range(0, 5)
REST_ITERATED_ENDPOINT_TEMPLATES: tuple[tuple[str, Iterable[int]], ...] = (
    ("rest/status/feed/{i}", REST_FEED_INDEXES),
)


# ID-discovered REST endpoints (build from returned JSON payloads).
# Each spec is: (source_payload, list_key, id_key, endpoint_template)
# - source_payload: "status" or "config" (which response JSON to examine)
# - list_key: top-level key containing a list of objects
# - id_key: key within each object to use as the ID
# - endpoint_template: resulting endpoint path
REST_ID_DISCOVERY_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("config", "iconf", "did", "rest/config/iconf/{did}"),
    ("config", "oconf", "did", "rest/config/oconf/{did}"),
    ("status", "inputs", "did", "rest/status/inputs/{did}"),
    ("status", "outputs", "did", "rest/status/outputs/{did}"),
)


def expand_endpoint_templates(
    base_endpoints: Iterable[str],
    templates: Iterable[tuple[str, Iterable[int]]],
) -> list[str]:
    """Expand endpoint templates like `rest/status/feed/{i}` into concrete endpoints."""

    out: list[str] = list(base_endpoints)
    for template, values in templates:
        tmpl = (template or "").strip().lstrip("/")
        if not tmpl:
            continue
        for i in values:
            out.append(tmpl.format(i=i))
    return out


CGI_BASE_ENDPOINTS: list[str] = [
    "cgi-bin/status.xml",
    "cgi-bin/status.json",
]

# Endpoints that exist in the UI but are not useful for the dumper:
# - form posts (fileload/filesave/status.cgi)
# - session/login endpoint
# - link/status helper with sensitive linkKey
IGNORED_ENDPOINT_PREFIXES: tuple[str, ...] = (
    "cgi-bin/fileload",
    "cgi-bin/filesave",
    "cgi-bin/status.cgi",
    "rest/login",
    "rest/status/link",
)


SENSITIVE_KEY_PATTERNS: tuple[str, ...] = (
    # Suffix '*' means "substring match" against the (lowercased) key.
    "username*",
    "login*",
    "password*",
    "passwd*",
    "secret*",
    "token*",
    "api_key*",
    "apikey*",
    "cookie*",
    "linkkey*",
    # Exact matches (no '*')
    "pass",
    "session",
    "ssid",
    "connect.sid",
)


def is_sensitive_key(key: str) -> bool:
    """Return True if a key name should be redacted."""

    k = (key or "").strip().lower()
    if not k:
        return False

    for pat in SENSITIVE_KEY_PATTERNS:
        p = pat.strip().lower()
        if not p:
            continue
        if p.endswith("*"):
            needle = p[:-1]
            if needle and needle in k:
                return True
        else:
            if k == p:
                return True

    return False


# ---------------------------
# Basic utilities
# ---------------------------


def setup_logging(verbose: bool) -> None:
    """Configure global console logging.

    Args:
        verbose: If True, sets log level to DEBUG. Otherwise INFO.

    Returns:
        None
    """
    handler = logging.StreamHandler()

    try:
        from colorlog import ColoredFormatter

        handler.setFormatter(
            ColoredFormatter(
                "%(log_color)s%(levelname)-8s%(reset)s: %(message)s",
                log_colors={
                    "DEBUG": "cyan",
                    "INFO": "green",
                    "WARNING": "yellow",
                    "ERROR": "red",
                    "CRITICAL": "bold_red",
                },
            )
        )
    except Exception:
        handler.setFormatter(logging.Formatter("%(levelname)-8s: %(message)s"))

    root = logging.getLogger()
    root.handlers[:] = []
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


def load_dotenv_simple(dotenv_path: Path) -> dict[str, str]:
    """Parse a very small .env file (KEY=VALUE, no exports).

    Args:
        dotenv_path: Path to the `.env` file.

    Returns:
        Mapping of keys to values.
    """
    if not dotenv_path.exists():
        return {}

    out: dict[str, str] = {}
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            out[key] = val
    return out


def apply_dotenv(dotenv_path: Path) -> None:
    """Load dotenv and apply only missing vars into `os.environ`.

    Existing environment variables are not overwritten.

    Args:
        dotenv_path: Path to the `.env` file.

    Returns:
        None
    """
    env = load_dotenv_simple(dotenv_path)
    for k, v in env.items():
        if k and k not in os.environ:
            os.environ[k] = v


def apply_dotenv_if_present() -> None:
    """Auto-load a `.env` file if one exists.

    Search order:
      1) Current working directory `.env`
      2) Repository root `.env` (parent of `.dev/`)
      3) `.dev/.env`

    Returns:
        None
    """

    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
        Path(__file__).resolve().parent / ".env",
    ]
    for p in candidates:
        if p.exists():
            apply_dotenv(p)
            return


@dataclass(frozen=True)
class Device:
    name: str
    base_url: str


_DEVICE_RE = re.compile(r"^(?:(?P<name>[A-Za-z0-9_-]+)@)?(?P<host>https?://.+|[^@]+)$")


def normalize_base_url(host: str) -> str:
    """Normalize a host into a base URL with scheme and trailing slash.

    Args:
        host: Hostname/IP or full URL.

    Returns:
        Normalized base URL ending with '/'.
    """
    h = (host or "").strip()
    if not h:
        raise ValueError("Empty device host")
    if not h.startswith("http://") and not h.startswith("https://"):
        h = f"http://{h}"
    if not h.endswith("/"):
        h += "/"
    return h


def parse_device_spec(spec: str) -> Device:
    """Parse a device spec of form `name@host` or `host`.

    Args:
        spec: Device spec string.

    Returns:
        Parsed `Device`.
    """
    m = _DEVICE_RE.match((spec or "").strip())
    if not m:
        raise ValueError(f"Invalid device spec: {spec!r} (expected name@host or host)")

    base_url = normalize_base_url(m.group("host"))
    name = m.group("name")
    if not name:
        derived = base_url.replace("http://", "").replace("https://", "").strip("/")
        name = derived.replace(":", "_")

    return Device(name=name, base_url=base_url)


def devices_from_env() -> list[Device]:
    """Parse devices from the environment.

    Preferred:
        - `APEX_IPS` as a comma-separated list of IPs/hosts.

    Backwards compatible:
        - `APEX_DEVICES` as a comma-separated list of `name@host` or `host`.

    Returns:
        List of parsed `Device` entries.
    """
    raw = os.getenv("APEX_IPS", "").strip() or os.getenv("APEX_DEVICES", "").strip()
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return [parse_device_spec(p) for p in parts]


def filter_ignored_endpoints(paths: list[str]) -> list[str]:
    """Filter out endpoints we never want to dump."""

    out: list[str] = []
    for raw in paths:
        p = (raw or "").strip().lstrip("/")
        if not p:
            continue
        if any(p.startswith(prefix) for prefix in IGNORED_ENDPOINT_PREFIXES):
            continue
        out.append(p)
    return out


def basic_auth_header(username: str, password: str) -> str:
    """Build a Basic Authorization header value.

    Args:
        username: Username.
        password: Password.

    Returns:
        Header value like `Basic <base64>`.
    """
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def http_request(
    opener: OpenerDirector,
    *,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout_seconds: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    """Make an HTTP request via urllib and return status, headers, body.

    Args:
        opener: An `urllib` opener.
        method: HTTP method.
        url: Absolute URL.
        headers: Optional request headers.
        body: Optional request body bytes.
        timeout_seconds: Request timeout in seconds.

    Returns:
        Tuple of (status, headers, body) where headers are lowercased.
    """
    req = Request(url, data=body, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            status = int(getattr(resp, "status", 200))
            resp_headers: dict[str, str] = {
                str(k).lower(): str(v) for (k, v) in resp.headers.items()
            }
            data = resp.read() or b""
            return status, resp_headers, data
    except HTTPError as e:
        resp_headers: dict[str, str] = {
            str(k).lower(): str(v) for (k, v) in getattr(e, "headers", {}).items()
        }
        data = e.read() if hasattr(e, "read") else b""
        return int(getattr(e, "code", 0) or 0), resp_headers, data


def endpoint_path_from_url(url: str) -> str:
    """Extract a stable endpoint path from a URL.

    This strips any query string so cache-busters like `?12345` don't create
    extra directories.

    Args:
        url: Absolute URL.

    Returns:
        Path beginning with '/', or '/' if missing.
    """

    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def dest_dir_for_endpoint(endpoint_path: str, root: Path) -> Path:
    """Convert an endpoint path into its fixture directory.

    Args:
        endpoint_path: Endpoint path like ``/cgi-bin/status.xml`` or ``/``.
        root: Root directory for this device dump.

    Returns:
        Directory path where this endpoint's `data` file should be written.
    """

    ep = (endpoint_path or "/").strip()
    if not ep.startswith("/"):
        ep = "/" + ep
    if ep == "/":
        return root / "_root"
    return root / ep.lstrip("/")


def format_json_bytes(data: bytes) -> bytes:
    """Pretty-format JSON bytes.

    Args:
        data: Raw JSON bytes.

    Returns:
        Pretty JSON bytes ending in a newline, or the original bytes if not JSON.
    """

    def redaction_enabled() -> bool:
        val = (os.getenv("APEX_REDACT", "1") or "1").strip().lower()
        return val not in {"0", "false", "no", "off"}

    def redact_obj(obj: Any) -> Any:
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            in_dict = cast(dict[Any, Any], obj)
            for raw_key, value in in_dict.items():
                key = str(raw_key)
                if is_sensitive_key(key) and redaction_enabled():
                    out[key] = "***REDACTED***"
                else:
                    out[key] = redact_obj(value)
            return out
        if isinstance(obj, list):
            in_list = cast(list[Any], obj)
            return [redact_obj(v) for v in in_list]
        return obj

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data

    try:
        obj: Any = json.loads(text)
    except Exception:
        return data

    obj = redact_obj(obj)
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def format_xml_bytes(data: bytes) -> bytes:
    """Pretty-format XML bytes.

    Args:
        data: Raw XML bytes.

    Returns:
        Pretty XML bytes ending in a newline, or original bytes if parsing fails.
    """

    def redaction_enabled() -> bool:
        val = (os.getenv("APEX_REDACT", "1") or "1").strip().lower()
        return val not in {"0", "false", "no", "off"}

    def redact_dom(node: minidom.Node, *, doc: minidom.Document) -> None:
        if node.nodeType == node.ELEMENT_NODE:
            elem = cast(minidom.Element, node)
            tag = elem.tagName
            if redaction_enabled() and is_sensitive_key(tag):
                # Remove children and replace with a single redacted text node.
                for child in list(elem.childNodes):
                    elem.removeChild(child)
                elem.appendChild(doc.createTextNode("***REDACTED***"))

            if elem.hasAttributes() and redaction_enabled():
                attrs = elem.attributes
                for i in range(attrs.length):
                    attr_node = attrs.item(i)
                    if attr_node is None:
                        continue
                    attr = cast(minidom.Attr, attr_node)
                    if is_sensitive_key(attr.name):
                        attr.value = "***REDACTED***"

        for child in list(node.childNodes):
            redact_dom(child, doc=doc)

    try:
        text = data.decode("utf-8", errors="replace")
        dom = minidom.parseString(text)
        redact_dom(dom, doc=dom)
        pretty = dom.toprettyxml(indent="  ", newl="\n")
        lines = [ln for ln in pretty.splitlines() if ln.strip()]
        out = "\n".join(lines) + "\n"
        return out.encode("utf-8")
    except (ExpatError, ValueError):
        return data


def _looks_like_xml_bytes(data: bytes) -> bool:
    """Heuristic to detect XML-like responses.

    Args:
        data: Raw response bytes.

    Returns:
        True if the bytes appear to be XML.
    """

    if not data:
        return False
    head = data[:200].lstrip().lower()
    return head.startswith(b"<?xml") or head.startswith(b"<")


def render_endpoint_data(
    *,
    endpoint_path: str,
    status: int,
    headers: dict[str, str],
    body: bytes,
) -> bytes:
    """Render the payload for the endpoint `data` file.

    Args:
        endpoint_path: Endpoint path, used only for metadata if body is empty.
        status: HTTP status code.
        headers: Response headers.
        body: Raw response bytes.

    Returns:
        Bytes to write to the `data` file.
    """

    if not body:
        meta = {
            "endpoint": endpoint_path,
            "status": status,
            "headers": headers,
            "body_len": 0,
        }
        return (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # Prefer content-type if available.
    ctype = (headers.get("content-type") or "").lower()
    if "json" in ctype:
        return format_json_bytes(body)
    if "xml" in ctype:
        return format_xml_bytes(body)

    # Fallback sniff.
    formatted_json = format_json_bytes(body)
    if formatted_json is not body:
        return formatted_json

    if _looks_like_xml_bytes(body):
        return format_xml_bytes(body)

    # Text fallback.
    try:
        text = body.decode("utf-8")
        if (os.getenv("APEX_REDACT", "1") or "1").strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }:
            # Conservative token-style redaction for plain text bodies.
            text = re.sub(r"(?i)(connect\.sid=)[^;\s]+", r"\1***REDACTED***", text)
            text = re.sub(
                r"(?i)(password\s*[:=]\s*)[^\s\n]+", r"\1***REDACTED***", text
            )
        if not text.endswith("\n"):
            text += "\n"
        return text.encode("utf-8")
    except UnicodeDecodeError:
        return body


def write_endpoint_fixture(
    out_root: Path,
    *,
    endpoint_path: str,
    status: int,
    headers: dict[str, str],
    body: bytes,
) -> None:
    """Write a single endpoint fixture under `<out_root>/<endpoint>/data`.

    Args:
        out_root: Root output directory for this device dump.
        endpoint_path: Endpoint path like ``/cgi-bin/status.xml``.
        status: HTTP status code.
        headers: Response headers.
        body: Raw response bytes.

    Returns:
        None
    """

    dest_dir = dest_dir_for_endpoint(endpoint_path, out_root)
    dest_dir.mkdir(parents=True, exist_ok=True)
    data_path = dest_dir / "data"
    data_path.write_bytes(
        render_endpoint_data(
            endpoint_path=endpoint_path,
            status=status,
            headers=headers,
            body=body,
        )
    )


# ---------------------------
# Dump
# ---------------------------


def try_new_api(
    device: Device,
    *,
    username: str,
    password: str,
    out_dir: Path,
    timeout: float,
    extra_endpoints: list[str],
) -> bool:
    """Attempt to dump endpoints from the newer `/rest/*` API.

    Args:
        device: Target device.
        username: Username.
        password: Password.
        out_dir: Output directory for this device dump.
        timeout: Request timeout seconds.

    Returns:
        True if login succeeded (HTTP 200), else False.
    """
    opener = build_opener(HTTPCookieProcessor())

    login_url = urljoin(device.base_url, "rest/login")
    payload = json.dumps(
        {"login": username, "password": password, "remember_me": False}
    ).encode("utf-8")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    st, _h, b = http_request(
        opener,
        method="POST",
        url=login_url,
        headers=headers,
        body=payload,
        timeout_seconds=timeout,
    )
    # Intentionally do not dump `/rest/login` (session endpoint).

    if st != 200:
        return False

    sid: str | None = None
    try:
        parsed_any: Any = json.loads(b.decode("utf-8")) if b else {}
        if isinstance(parsed_any, dict):
            parsed = cast(dict[str, Any], parsed_any)
            sid_val = parsed.get("connect.sid")
            sid = sid_val if isinstance(sid_val, str) and sid_val else None
    except Exception:
        sid = None

    req_headers: dict[str, str] = {"Accept": "application/json"}
    if sid:
        req_headers["Cookie"] = f"connect.sid={sid}"

    status_url = urljoin(device.base_url, "rest/status")
    st_status, h_status, b_status = http_request(
        opener,
        method="GET",
        url=status_url,
        headers=req_headers,
        timeout_seconds=timeout,
    )
    write_endpoint_fixture(
        out_dir,
        endpoint_path=endpoint_path_from_url(status_url),
        status=st_status,
        headers=h_status,
        body=b_status,
    )

    config_url = urljoin(device.base_url, "rest/config")
    st_config, h_config, b_config = http_request(
        opener,
        method="GET",
        url=config_url,
        headers=req_headers,
        timeout_seconds=timeout,
    )
    write_endpoint_fixture(
        out_dir,
        endpoint_path=endpoint_path_from_url(config_url),
        status=st_config,
        headers=h_config,
        body=b_config,
    )

    # Discover more endpoints from the returned JSON.
    # - Start from configured base endpoints + iterated templates.
    # - Add ID-discovered endpoints from the JSON payloads.
    discovered: list[str] = expand_endpoint_templates(
        REST_BASE_ENDPOINTS, REST_ITERATED_ENDPOINT_TEMPLATES
    )

    status_obj: dict[str, Any] | None = None
    if st_status == 200 and b_status:
        try:
            status_any: Any = json.loads(b_status.decode("utf-8"))
            if isinstance(status_any, dict):
                status_obj = cast(dict[str, Any], status_any)
        except Exception:
            status_obj = None

    config_obj: dict[str, Any] | None = None
    if st_config == 200 and b_config:
        try:
            config_any: Any = json.loads(b_config.decode("utf-8"))
            if isinstance(config_any, dict):
                config_obj = cast(dict[str, Any], config_any)
        except Exception:
            config_obj = None

    source_payloads: dict[str, dict[str, Any] | None] = {
        "status": status_obj,
        "config": config_obj,
    }

    for source_name, list_key, id_key, endpoint_tmpl in REST_ID_DISCOVERY_SPECS:
        src = source_payloads.get(source_name)
        if not isinstance(src, dict):
            continue
        items_any: Any = src.get(list_key)
        if not isinstance(items_any, list):
            continue
        for item_any in cast(list[Any], items_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, Any], item_any)
            did_any: Any = item.get(id_key)
            did = did_any if isinstance(did_any, str) else None
            if did:
                discovered.append(endpoint_tmpl.format(did=did))

    for ep in extra_endpoints:
        if ep:
            discovered.append(ep)

    discovered = filter_ignored_endpoints(discovered)

    # De-dup while keeping order.
    # Avoid re-fetching endpoints we already dumped above.
    already_dumped: set[str] = {
        endpoint_path_from_url(status_url).lstrip("/"),
        endpoint_path_from_url(config_url).lstrip("/"),
    }
    seen: set[str] = set(already_dumped)
    for path in discovered:
        if path in seen:
            continue
        seen.add(path)
        url = urljoin(device.base_url, path)
        try:
            st2, h2, b2 = http_request(
                opener,
                method="GET",
                url=url,
                headers=req_headers,
                timeout_seconds=timeout,
            )
        except Exception as e:
            write_endpoint_fixture(
                out_dir,
                endpoint_path=endpoint_path_from_url(url),
                status=0,
                headers={"error": str(e)},
                body=b"",
            )
            continue

        write_endpoint_fixture(
            out_dir,
            endpoint_path=endpoint_path_from_url(url),
            status=st2,
            headers=h2,
            body=b2,
        )

    return True


def try_legacy_api(
    device: Device,
    *,
    username: str,
    password: str,
    out_dir: Path,
    timeout: float,
    extra_endpoints: list[str],
) -> bool:
    """Attempt to dump endpoints from the legacy `/cgi-bin/*` API.

    Args:
        device: Target device.
        username: Username.
        password: Password.
        out_dir: Output directory for this device dump.
        timeout: Request timeout seconds.

    Returns:
        True if any legacy endpoint returned a non-empty HTTP 200 body.
    """
    opener = build_opener()

    headers = {"Accept": "*/*", "Authorization": basic_auth_header(username, password)}
    cb = str(int(time.time()))

    endpoints = [f"{p}?{cb}" for p in CGI_BASE_ENDPOINTS]
    for ep in extra_endpoints:
        if ep:
            endpoints.append(ep)

    endpoints = filter_ignored_endpoints(endpoints)

    ok = False
    for path in endpoints:
        url = urljoin(device.base_url, path)
        try:
            st, h, b = http_request(
                opener, method="GET", url=url, headers=headers, timeout_seconds=timeout
            )
        except Exception as e:
            write_endpoint_fixture(
                out_dir,
                endpoint_path=endpoint_path_from_url(url),
                status=0,
                headers={"error": str(e)},
                body=b"",
            )
            continue

        write_endpoint_fixture(
            out_dir,
            endpoint_path=endpoint_path_from_url(url),
            status=st,
            headers=h,
            body=b,
        )
        if st == 200 and b:
            ok = True

    return ok


def dump_device(
    device: Device, *, username: str, password: str, dumps_root: Path, timeout: float
) -> Path:
    """Dump a set of known endpoints from a single device.

    Args:
        device: Target device.
        username: Username.
        password: Password.
        dumps_root: Root dumps directory.
        timeout: Request timeout seconds.

    Returns:
        The created dump directory path.
    """
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = dumps_root / device.name / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    LOG.info("Dumping %s (%s)", device.name, device.base_url)
    (out_dir / "device.json").write_text(
        json.dumps({"name": device.name, "base_url": device.base_url}, indent=2),
        encoding="utf-8",
    )

    new_ok = False
    legacy_ok = False

    extra_env = os.getenv("APEX_EXTRA_ENDPOINTS", "").strip()
    extra_endpoints = [p.strip().lstrip("/") for p in extra_env.split(",") if p.strip()]

    extra_endpoints = filter_ignored_endpoints(extra_endpoints)

    # Route extra endpoints to the right API family.
    extra_rest_endpoints = [p for p in extra_endpoints if p.startswith("rest/")]
    extra_cgi_endpoints = [p for p in extra_endpoints if p.startswith("cgi-bin/")]

    if password:
        try:
            new_ok = try_new_api(
                device,
                username=username,
                password=password,
                out_dir=out_dir,
                timeout=timeout,
                extra_endpoints=extra_rest_endpoints,
            )
        except URLError as e:
            LOG.warning("New API unreachable for %s: %s", device.name, e)
        except Exception as e:
            LOG.warning("New API error for %s: %s", device.name, e)

        try:
            legacy_ok = try_legacy_api(
                device,
                username=username,
                password=password,
                out_dir=out_dir,
                timeout=timeout,
                extra_endpoints=extra_cgi_endpoints,
            )
        except URLError as e:
            LOG.warning("Legacy API unreachable for %s: %s", device.name, e)
        except Exception as e:
            LOG.warning("Legacy API error for %s: %s", device.name, e)
    else:
        # Still attempt legacy without auth to capture 401/realm headers.
        try:
            opener = build_opener()
            for path in ("cgi-bin/status.xml", "cgi-bin/status.json"):
                url = urljoin(device.base_url, path)
                st, h, b = http_request(
                    opener,
                    method="GET",
                    url=url,
                    headers={"Accept": "*/*"},
                    timeout_seconds=timeout,
                )
                write_endpoint_fixture(
                    out_dir,
                    endpoint_path=endpoint_path_from_url(url),
                    status=st,
                    headers=h,
                    body=b,
                )
        except Exception:
            pass

    (out_dir / "summary.json").write_text(
        json.dumps(
            {
                "device": device.name,
                "base_url": device.base_url,
                "new_api_ok": new_ok,
                "legacy_api_ok": legacy_ok,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return out_dir


# ---------------------------
# Scan
# ---------------------------


@dataclass(frozen=True)
class ScanResult:
    ip: str
    kind: str  # modern | legacy
    detail: str


def _looks_like_status_xml(body: bytes) -> bool:
    """Heuristic to detect an Apex `status.xml` response.

    Args:
        body: Raw response bytes.

    Returns:
        True if the bytes look like `<status ...>` XML.
    """
    if not body:
        return False
    head = body[:200].lower()
    return b"<status" in head or b"<status " in head


def probe_host_for_apex(
    ip: str, *, username: str, password: str, timeout: float
) -> ScanResult | None:
    """Best-effort probe for an Apex controller on a single IP.

    Args:
        ip: IP address string.
        username: Username.
        password: Password.
        timeout: Request timeout seconds.

    Returns:
        A `ScanResult` if the host looks like an Apex controller; otherwise None.
    """
    base = f"http://{ip}/"

    def probe_rest_presence() -> bool:
        """Return True if the REST API appears to exist.

        Rule: if `/rest/status` returns anything other than 404, we treat REST as present.
        This matches the practical expectation: "if rest/ exists, it's not legacy".
        """

        rest_url = urljoin(base, "rest/status")
        try:
            st, _h, _b = http_request(
                build_opener(),
                method="GET",
                url=rest_url,
                headers={"Accept": "application/json"},
                timeout_seconds=timeout,
            )
        except Exception:
            return False

        return st != 404

    used: list[str] = []

    # 1) REST presence check (no creds required)
    rest_present = probe_rest_presence()
    if rest_present:
        used.append("rest/status")

    # 2) CGI check: status.xml (still commonly present even on modern devices)
    cgi_present = False
    try:
        opener = build_opener()
        status_url = urljoin(base, "cgi-bin/status.xml")
        st2, _h2, b2 = http_request(
            opener,
            method="GET",
            url=status_url,
            headers={"Accept": "*/*"},
            timeout_seconds=timeout,
        )
        if st2 == 200 and _looks_like_status_xml(b2):
            cgi_present = True
            used.append("cgi-bin/status.xml")
    except Exception:
        cgi_present = False

    # Classification: exactly one of modern/legacy.
    if rest_present:
        return ScanResult(ip=ip, kind="modern", detail=", ".join(used))
    if cgi_present:
        return ScanResult(ip=ip, kind="legacy", detail=", ".join(used))

    return None


def scan_cidr(
    cidr: str,
    *,
    username: str,
    password: str,
    timeout: float,
    workers: int,
    max_hosts: int,
) -> list[ScanResult]:
    """Scan a CIDR range for Apex controllers.

    Args:
        cidr: CIDR to scan (e.g. `192.168.1.0/24`).
        username: Username used for confirmation probes.
        password: Password used for confirmation probes.
        timeout: Per-host timeout seconds.
        workers: Thread pool size.
        max_hosts: Refuse scans larger than this number of hosts.

    Returns:
        List of discovered Apex-like hosts.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    host_count = (
        int(max(0, net.num_addresses - 2))
        if getattr(net, "version", 4) == 4
        else int(net.num_addresses)
    )
    if host_count > max_hosts:
        raise ValueError(
            f"Refusing to scan {net} ({host_count} hosts). Increase --max-hosts to override."
        )

    ips = [str(ip) for ip in net.hosts()]

    found: list[ScanResult] = []

    def one(ip: str) -> ScanResult | None:
        try:
            return probe_host_for_apex(
                ip, username=username, password=password, timeout=timeout
            )
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for res in ex.map(one, ips, chunksize=32):
            if res is not None:
                found.append(res)

    return found


def print_scan_results(results: list[ScanResult]) -> None:
    """Print scan results in a simple table.

    Args:
        results: List of scan results.

    Returns:
        None
    """
    if not results:
        print("No Apex devices found.")
        return

    results = sorted(results, key=lambda r: (r.kind, r.ip))
    w_ip = max(2, max(len(r.ip) for r in results))
    w_kind = max(4, max(len(r.kind) for r in results))

    print(f"{'IP'.ljust(w_ip)}  {'KIND'.ljust(w_kind)}  DETAIL")
    print(f"{'-' * w_ip}  {'-' * w_kind}  {'-' * 6}")
    for r in results:
        print(f"{r.ip.ljust(w_ip)}  {r.kind.ljust(w_kind)}  {r.detail}")


# ---------------------------
# CLI
# ---------------------------


def cmd_dump(args: argparse.Namespace) -> int:
    """Handle the `dump` subcommand.

    Args:
        args: Parsed argparse namespace.

    Returns:
        Process exit code.
    """
    apply_dotenv_if_present()

    ip_specs = cast(list[str], getattr(args, "ip", []))
    devices: list[Device] = [
        parse_device_spec(d) for d in ip_specs
    ] or devices_from_env()
    if not devices:
        LOG.error("No IPs specified. Use --ip or set APEX_IPS.")
        return 2

    username = args.username or os.getenv("APEX_USERNAME") or "admin"
    password = (
        args.password
        if args.password is not None
        else (os.getenv("APEX_PASSWORD") or "")
    )

    dumps_root = Path(args.out_dir).resolve()
    dumps_root.mkdir(parents=True, exist_ok=True)

    for dev in devices:
        out_dir = dump_device(
            dev,
            username=username,
            password=password,
            dumps_root=dumps_root,
            timeout=float(args.timeout),
        )
        LOG.info("Wrote %s", out_dir)

    return 0


def cmd_get(args: argparse.Namespace) -> int:
    """Handle the `get` subcommand (fetch one endpoint and print).

    This is intentionally a lightweight debug helper: it logs in (if credentials
    are available) and then fetches a single endpoint path, printing the
    pretty-formatted body to stdout.
    """

    apply_dotenv_if_present()

    ip_specs = cast(list[str], getattr(args, "ip", []))
    devices: list[Device] = [
        parse_device_spec(d) for d in ip_specs
    ] or devices_from_env()
    if not devices:
        LOG.error("No IPs specified. Use --ip or set APEX_IPS.")
        return 2

    # For this helper, use the first provided device.
    device = devices[0]

    raw_path = (args.path or "").strip()
    if not raw_path:
        LOG.error("Provide --path (e.g. /rest/status or /apex/config/modules/4).")
        return 2

    username = args.username or os.getenv("APEX_USERNAME") or "admin"
    password = (
        args.password
        if args.password is not None
        else (os.getenv("APEX_PASSWORD") or "")
    )

    timeout = float(args.timeout)

    opener = build_opener(HTTPCookieProcessor())

    # If we have creds, attempt REST login first (best-effort).
    sid: str | None = None
    if password:
        try:
            login_url = urljoin(device.base_url, "rest/login")
            payload = json.dumps(
                {"login": username, "password": password, "remember_me": False}
            ).encode("utf-8")
            st_login, _h_login, b_login = http_request(
                opener,
                method="POST",
                url=login_url,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                body=payload,
                timeout_seconds=timeout,
            )
            if st_login == 200 and b_login:
                try:
                    login_any: Any = json.loads(b_login.decode("utf-8"))
                    if isinstance(login_any, dict):
                        login_obj = cast(dict[str, Any], login_any)
                        sid_any: Any = login_obj.get("connect.sid")
                        if isinstance(sid_any, str) and sid_any:
                            sid = sid_any
                except Exception:
                    sid = None
        except Exception:
            # Don't block the probe if login fails.
            sid = None

    # Build request URL: support absolute URLs, or paths relative to base_url.
    if raw_path.startswith("http://") or raw_path.startswith("https://"):
        url = raw_path
    else:
        url = urljoin(device.base_url, raw_path.lstrip("/"))

    req_headers: dict[str, str] = {"Accept": "application/json"}
    if sid:
        req_headers["Cookie"] = f"connect.sid={sid}"

    st, h, b = http_request(
        opener,
        method="GET",
        url=url,
        headers=req_headers,
        timeout_seconds=timeout,
    )

    # Print a tiny header, then the formatted body.
    print(f"{st} {endpoint_path_from_url(url)}")
    try:
        out = render_endpoint_data(
            endpoint_path=endpoint_path_from_url(url),
            status=st,
            headers=h,
            body=b,
        )
        print(out.decode("utf-8", errors="replace"), end="")
    except Exception:
        # As a last resort, dump raw bytes.
        try:
            print((b or b"").decode("utf-8", errors="replace"), end="")
        except Exception:
            pass

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle the `scan` subcommand.

    Args:
        args: Parsed argparse namespace.

    Returns:
        Process exit code.
    """
    apply_dotenv_if_present()

    username = args.username or os.getenv("APEX_USERNAME") or "admin"
    password = (
        args.password
        if args.password is not None
        else (os.getenv("APEX_PASSWORD") or "")
    )

    cidrs = list(cast(list[str], getattr(args, "cidr", [])) or [])
    if not cidrs:
        LOG.error("Provide at least one --cidr (e.g. 192.168.1.0/24).")
        return 2

    all_found: list[ScanResult] = []
    for cidr in cidrs:
        LOG.info("Scanning %s ...", cidr)
        found = scan_cidr(
            cidr,
            username=username,
            password=password,
            timeout=float(args.timeout),
            workers=int(args.workers),
            max_hosts=int(args.max_hosts),
        )
        all_found.extend(found)

    print_scan_results(all_found)

    # exit code: 0 if any found, 1 if none
    return 0 if all_found else 1


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured `argparse.ArgumentParser`.
    """

    class _FullHelpAction(argparse.Action):
        """Print top-level help plus each subcommand's help."""

        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: object,
            option_string: str | None = None,
        ) -> None:
            # Top-level help
            print(parser.format_help())

            # Subcommand help
            subparsers: dict[str, argparse.ArgumentParser] = getattr(
                parser, "_subcommand_parsers", {}
            )
            for name, subparser in subparsers.items():
                print("\n\n" + ("=" * 80))
                print(f"{name} command")
                print(("=" * 80) + "\n")
                print(subparser.format_help())

            parser.exit()

    p = argparse.ArgumentParser(
        prog="apex_dev.py",
        description="Apex dev helper",
        add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "-h",
        "--help",
        action=_FullHelpAction,
        nargs=0,
        help="Show this help message and exit (includes subcommand help)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan CIDRs for Apex controllers")
    scan.add_argument(
        "--cidr", action="append", help="CIDR to scan (repeatable), e.g. 192.168.1.0/24"
    )
    scan.add_argument(
        "--workers", type=int, default=128, help="Concurrent workers (default: 128)"
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Per-host HTTP timeout seconds (default: 1.5)",
    )
    scan.add_argument(
        "--max-hosts",
        type=int,
        default=4096,
        help="Refuse scanning bigger networks (default: 4096)",
    )
    scan.add_argument(
        "--username",
        default=None,
        help="Username (default: env/auto .env APEX_USERNAME or 'admin')",
    )
    scan.add_argument(
        "--password",
        default=None,
        help="Password (default: env/auto .env APEX_PASSWORD or empty)",
    )
    scan.set_defaults(func=cmd_scan)

    dump = sub.add_parser("dump", help="Dump raw payloads from Apex controllers")
    dump.add_argument(
        "--ip",
        action="append",
        default=[],
        help="Controller IP/host (repeatable)",
    )
    dump.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout seconds (default: 10)"
    )
    dump.add_argument(
        "--username",
        default=None,
        help="Username (default: env/auto .env APEX_USERNAME or 'admin')",
    )
    dump.add_argument(
        "--password",
        default=None,
        help="Password (default: env/auto .env APEX_PASSWORD or empty)",
    )
    dump.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parent / ".dev" / "dumps"),
        help="Output directory root (default: .dev/dumps)",
    )
    dump.set_defaults(func=cmd_dump)

    get = sub.add_parser("get", help="Fetch one endpoint and print response")
    get.add_argument(
        "--ip",
        action="append",
        default=[],
        help="Controller IP/host (repeatable; first is used)",
    )
    get.add_argument(
        "--path",
        required=True,
        help="Endpoint path or absolute URL (e.g. /apex/config/modules/4)",
    )
    get.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout seconds (default: 10)",
    )
    get.add_argument(
        "--username",
        default=None,
        help="Username (default: env/auto .env APEX_USERNAME or 'admin')",
    )
    get.add_argument(
        "--password",
        default=None,
        help="Password (default: env/auto .env APEX_PASSWORD or empty)",
    )
    get.set_defaults(func=cmd_get)

    # Used by the custom top-level help action.
    setattr(p, "_subcommand_parsers", {"scan": scan, "dump": dump, "get": get})

    return p


def main(argv: Iterable[str] | None = None) -> int:
    """Entrypoint for the CLI.

    Args:
        argv: Optional argv list. If None, uses `sys.argv`.

    Returns:
        Exit code.
    """
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    setup_logging(bool(args.verbose))
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
