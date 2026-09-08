#!/usr/bin/env python3
"""Googlevideo-Blocklist-Fänger mit AdGuard-DNS- und GitHub-Synchronisierung.

Der Dienst liest ausschließlich die offizielle AdGuard-DNS-Query-Log-API mit
persönlichem API-Key, erkennt googlevideo.com-Hosts und veröffentlicht eine
aktualisierte AdGuard-kompatible Blockliste im konfigurierten GitHub-Repository.
Lokale DNS-Logs und DoH-Zugangsdaten werden nicht verwendet.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Set

LOG = logging.getLogger("googlevideo-fanger")
ADGUARD_DNS_API_URL = "https://api.adguard-dns.io"
GITHUB_API_URL = "https://api.github.com"
DEFAULT_GITHUB_REPOSITORY = "Blacky1999/Googlevideo-Blocklist-Fanger"
DEFAULT_ENV_FILE = Path("/etc/googlevideo-fanger.env")
DOMAIN_RE = re.compile(
    "(?i)(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*"
    "googlevideo\\.com(?![a-z0-9_.-])"
)
GOOGLEVIDEO_SUFFIX = ".googlevideo.com"
ROOT_DOMAIN = "googlevideo.com"
HttpOpener = Callable[..., Any]


@dataclass(frozen=True)
class Config:
    output: Path
    state: Path
    adguard_api_key: str
    github_token: str
    github_repository: str = DEFAULT_GITHUB_REPOSITORY
    github_branch: str = "main"
    github_blocklist_path: str = "googlevideo-blocklist.txt"
    interval: int = 300
    allowlist: Path | None = None
    lookback_seconds: int = 86400


def read_env_file(path: Path) -> dict[str, str]:
    """Liest eine einfache KEY=VALUE-Datei, ohne Shell-Code auszuführen."""
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8", errors="strict").splitlines(), 1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Ungültige Zeile {line_number} in {path}: KEY=VALUE erwartet.")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"Ungültiger Variablenname in {path}, Zeile {line_number}.")
        values[key] = value.strip().strip("'\"")
    return values


def setting(name: str, file_values: dict[str, str], default: str = "") -> str:
    """Umgebung hat Vorrang vor der geschützten Konfigurationsdatei."""
    return os.getenv(name, "").strip() or file_values.get(name, "").strip() or default


def normalize_host(host: str) -> str:
    value = host.strip().lower().strip("'\"`()[]{}<>")
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def is_googlevideo_host(host: str) -> bool:
    value = normalize_host(host)
    if value == ROOT_DOMAIN:
        return True
    if not value.endswith(GOOGLEVIDEO_SUFFIX):
        return False
    labels = value.split(".")
    return len(labels) >= 3 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    )


def extract_googlevideo_hosts(text: str) -> Set[str]:
    """Gibt vollständige Regex-Treffer aus den AdGuard-DNS-Domainfeldern zurück."""
    return {normalize_host(match.group(0)) for match in DOMAIN_RE.finditer(text)}


def load_allowlist(path: Path | None) -> Set[str]:
    if path is None or not path.exists():
        return set()
    result: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and is_googlevideo_host(line):
            result.add(normalize_host(line))
    return result


def _next_cursor(payload: dict[str, Any]) -> str | None:
    pages = payload.get("pages")
    if not isinstance(pages, list):
        return None
    current_numbers = [
        page.get("page_number")
        for page in pages
        if isinstance(page, dict) and page.get("current") is True
    ]
    if not current_numbers or not isinstance(current_numbers[0], int):
        return None
    current = current_numbers[0]
    candidates = [
        page
        for page in pages
        if isinstance(page, dict)
        and isinstance(page.get("page_number"), int)
        and page["page_number"] > current
        and isinstance(page.get("page_cursor"), str)
        and page["page_cursor"]
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda page: page["page_number"])["page_cursor"]


def _read_json_response(response: Any, source: str) -> Any:
    try:
        return json.loads(response.read().decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{source} lieferte kein gültiges JSON.") from exc


def _http_error(source: str, exc: urllib.error.HTTPError) -> RuntimeError:
    details = exc.read().decode("utf-8", errors="replace")[:500].strip()
    return RuntimeError(f"{source} HTTP-Fehler {exc.code}: {details or exc.reason}")


def read_adguard_dns_query_log(
    api_key: str,
    timeout: int = 30,
    lookback_seconds: int = 86400,
    opener: HttpOpener | None = None,
) -> str:
    """Liest alle verfügbaren Query-Log-Domainfelder per AdGuard-DNS-API-Key."""
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("ADGUARD_DNS_API_KEY ist leer.")
    if lookback_seconds <= 0:
        raise ValueError("ADGUARD_DNS_LOOKBACK_SECONDS muss größer als 0 sein.")

    open_url = opener or urllib.request.urlopen
    now_millis = int(time.time() * 1000)
    base_params = {
        "time_from_millis": now_millis - (lookback_seconds * 1000),
        "time_to_millis": now_millis,
        "search": "googlevideo.com",
        "limit": 1000,
    }
    domains: list[str] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    while True:
        params = dict(base_params)
        if cursor:
            params["cursor"] = cursor
        endpoint = ADGUARD_DNS_API_URL + "/oapi/v1/query_log?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(
            endpoint,
            headers={
                "Authorization": f"ApiKey {api_key}",
                "Accept": "application/json",
                "User-Agent": "Googlevideo-Blocklist-Fanger/1.1",
            },
            method="GET",
        )
        try:
            with open_url(request, timeout=timeout) as response:
                payload = _read_json_response(response, "AdGuard-DNS-API")
        except urllib.error.HTTPError as exc:
            raise _http_error("AdGuard-DNS-API", exc) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"AdGuard-DNS-API Netzwerkfehler: {exc.reason}") from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise RuntimeError("Unerwartete AdGuard-DNS-Query-Log-Antwort.")
        domains.extend(
            str(item.get("domain", ""))
            for item in payload["items"]
            if isinstance(item, dict) and item.get("domain")
        )

        next_cursor = _next_cursor(payload)
        if not next_cursor or next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor
        if len(seen_cursors) >= 100:
            raise RuntimeError("AdGuard-DNS-Pagination nach 100 Seiten abgebrochen.")

    return "\n".join(domains)


def _github_path(repository: str, path: str) -> tuple[str, str, str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("GITHUB_REPOSITORY muss dem Format EIGENTÜMER/REPOSITORY entsprechen.")
    cleaned_path = path.strip().strip("/")
    if not cleaned_path or ".." in cleaned_path.split("/"):
        raise ValueError("GITHUB_BLOCKLIST_PATH muss ein sicherer relativer Repository-Pfad sein.")
    owner, repo = repository.split("/", 1)
    return owner, repo, urllib.parse.quote(cleaned_path, safe="/")


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Googlevideo-Blocklist-Fanger/1.1",
    }


def _get_github_file(
    token: str,
    repository: str,
    branch: str,
    path: str,
    timeout: int,
    opener: HttpOpener,
) -> tuple[str | None, bytes | None]:
    owner, repo, encoded_path = _github_path(repository, path)
    endpoint = (
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{encoded_path}?"
        + urllib.parse.urlencode({"ref": branch})
    )
    request = urllib.request.Request(endpoint, headers=_github_headers(token), method="GET")
    try:
        with opener(request, timeout=timeout) as response:
            payload = _read_json_response(response, "GitHub-API")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, None
        raise _http_error("GitHub-API", exc) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub-API Netzwerkfehler: {exc.reason}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("sha"), str):
        raise RuntimeError("Unerwartete GitHub-API-Antwort beim Lesen der Blockliste.")
    content = payload.get("content", "")
    if not isinstance(content, str):
        raise RuntimeError("GitHub-API-Antwort enthält keinen lesbaren Dateiinhalt.")
    try:
        return payload["sha"], base64.b64decode(content.encode("ascii"), validate=False)
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("GitHub-API-Antwort enthält ungültige Base64-Daten.") from exc


def publish_blocklist_to_github(
    content: str,
    host_count: int,
    token: str,
    repository: str = DEFAULT_GITHUB_REPOSITORY,
    branch: str = "main",
    path: str = "googlevideo-blocklist.txt",
    timeout: int = 30,
    opener: HttpOpener | None = None,
) -> bool:
    """Schreibt die Blockliste nur bei Änderung über die GitHub Contents API."""
    token = token.strip()
    if not token:
        raise ValueError("GITHUB_TOKEN ist leer.")
    if not branch.strip():
        raise ValueError("GITHUB_BRANCH darf nicht leer sein.")

    open_url = opener or urllib.request.urlopen
    existing_sha, existing_content = _get_github_file(
        token, repository, branch, path, timeout, open_url
    )
    encoded_content = content.encode("utf-8")
    if existing_content == encoded_content:
        return False

    owner, repo, encoded_path = _github_path(repository, path)
    payload: dict[str, str] = {
        "message": f"chore(blocklist): update {host_count} googlevideo hosts",
        "content": base64.b64encode(encoded_content).decode("ascii"),
        "branch": branch,
    }
    if existing_sha:
        payload["sha"] = existing_sha
    request = urllib.request.Request(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{encoded_path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={**_github_headers(token), "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with open_url(request, timeout=timeout) as response:
            result = _read_json_response(response, "GitHub-API")
    except urllib.error.HTTPError as exc:
        raise _http_error("GitHub-API", exc) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub-API Netzwerkfehler: {exc.reason}") from exc
    if not isinstance(result, dict) or not isinstance(result.get("commit"), dict):
        raise RuntimeError("Unerwartete GitHub-API-Antwort beim Schreiben der Blockliste.")
    return True


def render_blocklist(hosts: Iterable[str]) -> str:
    ordered = sorted(set(hosts))
    lines = [
        "! Title: Googlevideo-Blocklist-Fanger",
        "! Generated from AdGuard DNS Query Logs",
        "! Synced automatically to GitHub when changed",
        f"! Entries: {len(ordered)}",
        "",
    ]
    lines.extend(f"||{host}^" for host in ordered)
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_state(
    path: Path,
    hosts: Set[str],
    output: str,
    github_updated: bool,
    repository: str,
    github_path: str,
) -> None:
    payload = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "adguard-dns-query-log-api",
        "entries": len(hosts),
        "github_repository": repository,
        "github_path": github_path,
        "github_updated": github_updated,
        "sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
    }
    atomic_write(path, json.dumps(payload, indent=2) + "\n")


def run_once(
    config: Config,
    adguard_opener: HttpOpener | None = None,
    github_opener: HttpOpener | None = None,
) -> Set[str]:
    source_text = read_adguard_dns_query_log(
        config.adguard_api_key,
        lookback_seconds=config.lookback_seconds,
        opener=adguard_opener,
    )
    discovered = extract_googlevideo_hosts(source_text)
    hosts = discovered - load_allowlist(config.allowlist)
    rendered = render_blocklist(hosts)
    atomic_write(config.output, rendered)
    github_updated = publish_blocklist_to_github(
        rendered,
        len(hosts),
        config.github_token,
        config.github_repository,
        config.github_branch,
        config.github_blocklist_path,
        opener=github_opener,
    )
    write_state(
        config.state,
        hosts,
        rendered,
        github_updated,
        config.github_repository,
        config.github_blocklist_path,
    )
    github_status = "aktualisiert" if github_updated else "unverändert"
    LOG.info(
        "API-Zyklus beendet: %d Hosts erkannt, %d freigegeben, GitHub %s: %s/%s",
        len(discovered),
        len(hosts),
        github_status,
        config.github_repository,
        config.github_blocklist_path,
    )
    return hosts


def parse_args(argv: list[str] | None = None) -> tuple[argparse.Namespace, dict[str, str]]:
    preliminary = argparse.ArgumentParser(add_help=False)
    preliminary.add_argument(
        "--env-file",
        type=Path,
        default=Path(os.getenv("GV_ENV_FILE", str(DEFAULT_ENV_FILE))),
    )
    known, _ = preliminary.parse_known_args(argv)
    # systemd lädt diese Datei bereits vor dem unprivilegierten Prozess. Bei
    # manuellem sudo-Start wird sie hier gelesen, damit der Key verfügbar ist.
    required_env = ("ADGUARD_DNS_API_KEY", "GITHUB_TOKEN")
    file_values = (
        {}
        if all(os.getenv(name, "").strip() for name in required_env)
        else read_env_file(known.env_file)
    )

    parser = argparse.ArgumentParser(description=__doc__, parents=[preliminary])
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(setting("GV_OUTPUT", file_values, "./googlevideo-blocklist.txt")),
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(setting("GV_STATE", file_values, "./googlevideo-state.json")),
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(setting("GV_ALLOWLIST", file_values, "./allowlist.txt")),
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(setting("GV_INTERVAL", file_values, "300")),
    )
    parser.add_argument(
        "--lookback-seconds",
        type=int,
        default=int(setting("ADGUARD_DNS_LOOKBACK_SECONDS", file_values, "86400")),
    )
    parser.add_argument(
        "--github-repository",
        default=setting("GITHUB_REPOSITORY", file_values, DEFAULT_GITHUB_REPOSITORY),
    )
    parser.add_argument(
        "--github-branch",
        default=setting("GITHUB_BRANCH", file_values, "main"),
    )
    parser.add_argument(
        "--github-blocklist-path",
        default=setting("GITHUB_BLOCKLIST_PATH", file_values, "googlevideo-blocklist.txt"),
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-level", default=setting("GV_LOG_LEVEL", file_values, "INFO"))
    return parser.parse_args(argv), file_values


def main(argv: list[str] | None = None) -> int:
    args, file_values = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    adguard_api_key = setting("ADGUARD_DNS_API_KEY", file_values)
    github_token = setting("GITHUB_TOKEN", file_values)
    missing = [
        name
        for name, value in (
            ("ADGUARD_DNS_API_KEY", adguard_api_key),
            ("GITHUB_TOKEN", github_token),
        )
        if not value
    ]
    if missing:
        LOG.error("Erforderliche Konfiguration fehlt in %s: %s", args.env_file, ", ".join(missing))
        return 2
    if args.interval < 30:
        LOG.error("Intervall muss mindestens 30 Sekunden betragen.")
        return 2

    config = Config(
        output=args.output,
        state=args.state,
        adguard_api_key=adguard_api_key,
        github_token=github_token,
        github_repository=args.github_repository,
        github_branch=args.github_branch,
        github_blocklist_path=args.github_blocklist_path,
        interval=args.interval,
        allowlist=args.allowlist,
        lookback_seconds=args.lookback_seconds,
    )
    while True:
        try:
            run_once(config)
        except Exception as exc:
            LOG.exception("Aktualisierung fehlgeschlagen: %s", exc)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(config.interval)


if __name__ == "__main__":
    sys.exit(main())
