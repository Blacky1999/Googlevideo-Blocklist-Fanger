#!/usr/bin/env python3
"""Googlevideo-Blocklist-Fänger.

Liest eine lokale DNS-/Proxy-Logdatei, erkennt googlevideo.com-Hosts und schreibt
alle fünf Minuten eine kumulative AdGuard-kompatible Blockliste. Es werden keine
externen Blocklisten geladen und keine Netzwerkverbindungen aufgebaut.
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
from typing import Any, Iterable, Set

LOG = logging.getLogger("googlevideo-fanger")
# Einzeiliger Regex für die Log-Suche: exakt googlevideo.com sowie
# *.googlevideo.com; kein optionaler Abschluss-Punkt.
DOMAIN_RE = re.compile("(?i)(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*googlevideo\\.com(?![a-z0-9_.-])")
GOOGLEVIDEO_SUFFIX = ".googlevideo.com"
ROOT_DOMAIN = "googlevideo.com"


@dataclass(frozen=True)
class Config:
    source: Path
    output: Path
    state: Path
    interval: int = 300
    allowlist: Path | None = None
    adguard_api_url: str | None = None
    adguard_api_key: str | None = None
    adguard_auth_mode: str = "apikey"
    adguard_lookback_seconds: int = 86400


def normalize_host(host: str) -> str:
    """Normalisiert einen DNS-Namen ohne Port, Punkt oder URL-Schema."""
    value = host.strip().lower().strip("'\"`()[]{}<>")
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def is_googlevideo_host(host: str) -> bool:
    """Akzeptiert googlevideo.com und beliebige gültige Subdomains davon."""
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
    """Gibt exakt die vollständigen Regex-Treffer aus dns.log zurück."""
    return {
        normalize_host(match.group(0))
        for match in DOMAIN_RE.finditer(text)
    }


def load_allowlist(path: Path | None) -> Set[str]:
    if path is None or not path.exists():
        return set()
    result: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and is_googlevideo_host(line):
            result.add(normalize_host(line))
    return result


def read_source(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Quelle nicht gefunden: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def read_adguard_dns_query_log(
    api_url: str,
    api_key: str,
    auth_mode: str = "apikey",
    timeout: int = 30,
    lookback_seconds: int = 86400,
) -> str:
    """Liest Query-Log-Domainfelder über die offizielle AdGuard-DNS-API."""
    if lookback_seconds <= 0:
        raise ValueError("ADGUARD_DNS_LOOKBACK_SECONDS muss größer als 0 sein.")
    now_millis = int(time.time() * 1000)
    query = urllib.parse.urlencode(
        {
            "time_from_millis": now_millis - (lookback_seconds * 1000),
            "time_to_millis": now_millis,
            "search": "googlevideo.com",
            "limit": 1000,
        }
    )
    endpoint = api_url.rstrip("/") + "/oapi/v1/query_log?" + query
    mode = auth_mode.strip().lower()
    if mode == "bearer":
        authorization = f"Bearer {api_key.strip()}"
    elif mode == "apikey":
        authorization = f"ApiKey {api_key.strip()}"
    else:
        raise ValueError("ADGUARD_DNS_AUTH_MODE muss 'apikey' oder 'bearer' sein.")
    request = urllib.request.Request(
        endpoint,
        headers={"Authorization": authorization, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload: Any = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(
            f"AdGuard-DNS-API HTTP-Fehler {exc.code}: {details}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AdGuard-DNS-API Netzwerkfehler: {exc.reason}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise RuntimeError("Unerwartete AdGuard-DNS-Query-Log-Antwort.")
    return "\n".join(
        str(item.get("domain", ""))
        for item in payload["items"]
        if isinstance(item, dict)
    )


def render_blocklist(hosts: Iterable[str]) -> str:
    ordered = sorted(set(hosts))
    lines = [
        "! Title: Googlevideo-Blocklist-Fanger",
        "! Generated by googlevideo_fanger.py",
        "! AdGuard syntax: blocks googlevideo.com hosts discovered in local logs",
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
        "entries": len(hosts),
        "sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
    }
    atomic_write(path, json.dumps(payload, indent=2) + "\n")


def run_once(config: Config) -> Set[str]:
    if config.adguard_api_url and config.adguard_api_key:
        source_text = read_adguard_dns_query_log(
            config.adguard_api_url,
            config.adguard_api_key,
            config.adguard_auth_mode,
            lookback_seconds=config.adguard_lookback_seconds,
        )
    else:
        source_text = read_source(config.source)
    discovered = extract_googlevideo_hosts(source_text)
    excluded = load_allowlist(config.allowlist)
    hosts = discovered - excluded
    rendered = render_blocklist(hosts)
    atomic_write(config.output, rendered)
    write_state(config.state, hosts, rendered)
    LOG.info("Zyklus beendet: %d Hosts erkannt, %d freigegeben, Ausgabe: %s", len(discovered), len(hosts), config.output)
    return hosts


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(os.getenv("GV_SOURCE", "./dns.log")))
    parser.add_argument("--output", type=Path, default=Path(os.getenv("GV_OUTPUT", "./googlevideo-blocklist.txt")))
    parser.add_argument("--state", type=Path, default=Path(os.getenv("GV_STATE", "./googlevideo-state.json")))
    parser.add_argument("--allowlist", type=Path, default=Path(os.getenv("GV_ALLOWLIST", "./allowlist.txt")))
    parser.add_argument("--interval", type=int, default=int(os.getenv("GV_INTERVAL", "300")))
    parser.add_argument(
        "--adguard-api-url",
        default=os.getenv("ADGUARD_DNS_API_URL"),
        help="AdGuard-DNS-API-Basis-URL, z. B. https://api.adguard-dns.io",
    )
    parser.add_argument(
        "--adguard-auth-mode",
        default=os.getenv("ADGUARD_DNS_AUTH_MODE", "apikey"),
        choices=("apikey", "bearer"),
    )
    parser.add_argument(
        "--adguard-lookback-seconds",
        type=int,
        default=int(os.getenv("ADGUARD_DNS_LOOKBACK_SECONDS", "86400")),
        help="Zeitraum des Online-Query-Logs, Standard: 86400 Sekunden",
    )
    parser.add_argument("--once", action="store_true", help="Nur einen Aktualisierungszyklus ausführen")
    parser.add_argument("--log-level", default=os.getenv("GV_LOG_LEVEL", "INFO"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(message)s")
    if args.interval < 30:
        LOG.error("Intervall muss mindestens 30 Sekunden betragen.")
        return 2
    config = Config(
        args.source,
        args.output,
        args.state,
        args.interval,
        args.allowlist,
        args.adguard_api_url,
        os.getenv("ADGUARD_DNS_API_KEY", "").strip() or None,
        args.adguard_auth_mode,
        args.adguard_lookback_seconds,
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
