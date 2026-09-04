#!/usr/bin/env python3
"""Googlevideo-Blocklist-Fänger über die AdGuard-DNS-Query-Log-API.

Der Dienst liest ausschließlich die offizielle AdGuard-DNS-Query-Log-API,
filtert googlevideo.com-Hosts und schreibt eine AdGuard-kompatible Blockliste.
Lokale DNS-Logdateien, DoH-Zugangsdaten und Bearer-Token werden nicht verwendet.
"""
from __future__ import annotations

import argparse
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
DEFAULT_ENV_FILE = Path("/etc/googlevideo-fanger.env")
DOMAIN_RE = re.compile("(?i)(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*googlevideo\\.com(?![a-z0-9_.-])")
GOOGLEVIDEO_SUFFIX = ".googlevideo.com"
ROOT_DOMAIN = "googlevideo.com"


@dataclass(frozen=True)
class Config:
    output: Path
    state: Path
    api_key: str
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
    """Gibt vollständige Regex-Treffer aus den API-Domainfeldern zurück."""
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


def read_adguard_dns_query_log(
    api_key: str,
    timeout: int = 30,
    lookback_seconds: int = 86400,
    opener: Callable[..., Any] | None = None,
) -> str:
    """Liest alle verfügbaren Query-Log-Domainfelder per AdGuard API-Key."""
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
        endpoint = (
            ADGUARD_DNS_API_URL
            + "/oapi/v1/query_log?"
            + urllib.parse.urlencode(params)
        )
        request = urllib.request.Request(
            endpoint,
            headers={
                "Authorization": f"ApiKey {api_key}",
                "Accept": "application/json",
                "User-Agent": "Googlevideo-Blocklist-Fanger/1.0",
            },
            method="GET",
        )
        try:
            with open_url(request, timeout=timeout) as response:
                payload: Any = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(
                f"AdGuard-DNS-API HTTP-Fehler {exc.code}: {details or exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"AdGuard-DNS-API Netzwerkfehler: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("AdGuard-DNS-API lieferte kein gültiges JSON.") from exc

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


def render_blocklist(hosts: Iterable[str]) -> str:
    ordered = sorted(set(hosts))
    lines = [
        "! Title: Googlevideo-Blocklist-Fanger",
        "! Generated from AdGuard DNS Query Logs via API key",
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


def write_state(path: Path, hosts: Set[str], output: str) -> None:
    payload = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "adguard-dns-query-log-api",
        "entries": len(hosts),
        "sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
    }
    atomic_write(path, json.dumps(payload, indent=2) + "\n")


def run_once(config: Config, opener: Callable[..., Any] | None = None) -> Set[str]:
    source_text = read_adguard_dns_query_log(
        config.api_key,
        lookback_seconds=config.lookback_seconds,
        opener=opener,
    )
    discovered = extract_googlevideo_hosts(source_text)
    hosts = discovered - load_allowlist(config.allowlist)
    rendered = render_blocklist(hosts)
    atomic_write(config.output, rendered)
    write_state(config.state, hosts, rendered)
    LOG.info(
        "API-Zyklus beendet: %d Hosts erkannt, %d freigegeben, Ausgabe: %s",
        len(discovered),
        len(hosts),
        config.output,
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
    # systemd liest EnvironmentFile als Manager ein, bevor der unprivilegierte
    # Dienst startet. Dann muss das Skript die root-only-Datei nicht erneut lesen.
    file_values = (
        {}
        if os.getenv("ADGUARD_DNS_API_KEY", "").strip()
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
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--log-level", default=setting("GV_LOG_LEVEL", file_values, "INFO")
    )
    return parser.parse_args(argv), file_values


def main(argv: list[str] | None = None) -> int:
    args, file_values = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    api_key = setting("ADGUARD_DNS_API_KEY", file_values)
    if not api_key:
        LOG.error(
            "ADGUARD_DNS_API_KEY fehlt. Trage ihn in %s ein oder exportiere ihn.",
            args.env_file,
        )
        return 2
    if args.interval < 30:
        LOG.error("Intervall muss mindestens 30 Sekunden betragen.")
        return 2

    config = Config(
        output=args.output,
        state=args.state,
        api_key=api_key,
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
