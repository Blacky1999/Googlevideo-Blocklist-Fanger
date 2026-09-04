# Googlevideo-Blocklist-Fanger

Ein kleiner, serverfähiger Python-Dienst, der die offiziellen AdGuard-DNS-Query-Logs nach `googlevideo.com`-Domains und Subdomains durchsucht und daraus alle fünf Minuten eine **AdGuard-kompatible Blockliste** erzeugt.

## Was der Dienst macht

Der Fänger verwendet ausschließlich die AdGuard-DNS-Query-Log-API. Die Erkennung der aus der API gelieferten `domain`-Felder verwendet genau diesen einzeiligen Python-Regex:

```python
re.compile("(?i)(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*googlevideo\\.com(?![a-z0-9_.-])")
```

Das `*` in `*.googlevideo.com` wird durch das wiederholbare Subdomain-Label im Regex abgedeckt. Dadurch werden sowohl `one.googlevideo.com` als auch `two.three.googlevideo.com` erkannt. Die Logsuche verwendet ausschließlich diesen Regex: Ein abschließender DNS-Punkt wie in `a.googlevideo.com.` wird absichtlich nicht als Treffer akzeptiert. Aus einer Zeile wie `query r1---sn-ab5l6n7e.googlevideo.com` wird ausschließlich der vollständige Treffer `r1---sn-ab5l6n7e.googlevideo.com` übernommen. Der Fänger dedupliziert Treffer, entfernt optionale Allowlist-Einträge und schreibt die Blockliste atomar. Dadurch lesen DNS-/AdGuard-Clients entweder die alte oder die vollständige neue Datei, niemals eine halbfertige Datei.

Der Regex wird auf die aus den API-Antworten gelesenen `domain`-Werte angewandt. Ein abschließender DNS-Punkt wird absichtlich nicht akzeptiert. Der Dienst lädt keine fremden Blocklisten und leitet keine Query-Log-Daten weiter.

## AdGuard DNS online: Query-Log-API

`https://d.adguard-dns.com/dns-query` ist ausschließlich ein DNS-over-HTTPS-Endpunkt. Er nimmt DNS-Anfragen entgegen, stellt aber keine Query-Logs bereit. Für die Online-Logs verwendet der Fänger deshalb die offizielle API:

```text
https://api.adguard-dns.io/oapi/v1/query_log
```

Die API verlangt zusätzlich ein Zeitfenster. Der Dienst setzt deshalb bei jedem Lauf automatisch `time_from_millis` und `time_to_millis`, standardmäßig für die letzten 24 Stunden, sowie `search=googlevideo.com` und `limit=1000`. Anschließend liest er die Felder `domain` aus. Die Authentifizierung wird ausschließlich über Umgebungsvariablen gesetzt:

```bash
export ADGUARD_DNS_API_URL="https://api.adguard-dns.io"
export ADGUARD_DNS_API_KEY="DEIN_ADGUARD_DNS_API_KEY"
export ADGUARD_DNS_AUTH_MODE="apikey"  # alternativ: bearer
export ADGUARD_DNS_LOOKBACK_SECONDS="86400"  # optional: 24 Stunden
python3 googlevideo_fanger.py --once
```

Der im Chat gepostete DoH-Link enthielt Zugangsdaten. Diese sollten sofort im AdGuard-Konto widerrufen beziehungsweise zurückgesetzt werden. DoH-Passwörter sind nicht automatisch API-Schlüssel und gehören nicht in `ADGUARD_DNS_API_KEY`.

> Hinweis: Eine Blockliste für `googlevideo.com` kann YouTube-Videoauslieferung, eingebettete Videos und andere Google-Video-Dienste beeinträchtigen. Nutze die Allowlist für benötigte Hosts.

## Serverbetrieb mit systemd

Die mitgelieferte Unit verwendet die Online-Query-Log-API und erwartet einen Debian-/Ubuntu-Server. Lege den API-Schlüssel in einer nicht versionierten Root-Datei ab:

```bash
sudo useradd --system --home /opt/googlevideo-blocklist-fanger --shell /usr/sbin/nologin googlevideo-fanger
sudo install -d -o googlevideo-fanger -g googlevideo-fanger /opt/googlevideo-blocklist-fanger /var/lib/googlevideo-fanger
sudo install -m 0755 googlevideo_fanger.py /opt/googlevideo-blocklist-fanger/googlevideo_fanger.py
sudo install -m 0600 /dev/null /etc/googlevideo-fanger.env
sudo sh -c 'printf "%s\\n" "ADGUARD_DNS_API_KEY=DEIN_API_KEY" "ADGUARD_DNS_AUTH_MODE=apikey" > /etc/googlevideo-fanger.env'
sudo install -m 0644 googlevideo-fanger.service /etc/systemd/system/googlevideo-fanger.service
sudo touch /etc/googlevideo-fanger-allowlist.txt
sudo chown root:root /etc/googlevideo-fanger-allowlist.txt
sudo systemctl daemon-reload
sudo systemctl enable --now googlevideo-fanger.service
sudo systemctl status googlevideo-fanger.service
```

Die erzeugte Datei liegt dann unter:

```text
/var/lib/googlevideo-fanger/googlevideo-blocklist.txt
```

Diese Datei kann in AdGuard Home, Pi-hole oder einem eigenen DNS-/Proxy-Setup als lokale Filterquelle eingebunden werden. Der Fänger selbst ändert keine DNS-Konfiguration automatisch.

## Konfiguration

| Variable/Argument | Standard | Bedeutung |
|---|---|---|
| `--adguard-api-url` / `ADGUARD_DNS_API_URL` | `https://api.adguard-dns.io` | AdGuard-DNS-API-Basis-URL |
| `ADGUARD_DNS_API_KEY` | keine | API-Schlüssel außerhalb des Repositories |
| `ADGUARD_DNS_AUTH_MODE` | `apikey` | `apikey` oder `bearer` |
| `ADGUARD_DNS_LOOKBACK_SECONDS` | `86400` | Zeitraum des Query-Logs |
| `--output` / `GV_OUTPUT` | `./googlevideo-blocklist.txt` | AdGuard-Ausgabe |
| `--state` / `GV_STATE` | `./googlevideo-state.json` | Status und Hash |
| `--allowlist` / `GV_ALLOWLIST` | `./allowlist.txt` | erlaubte googlevideo-Hosts, eine Domain pro Zeile |
| `--interval` / `GV_INTERVAL` | `300` | Aktualisierungsintervall in Sekunden |

Das Mindestintervall beträgt 30 Sekunden. Für die gewünschte Aktualisierung alle fünf Minuten bleibt der systemd-Wert `300`.

## Sicherheit und Grenzen

Der Dienst benötigt nur Leserechte auf die Quelldatei und Schreibrechte auf sein Ausgabeverzeichnis. Die systemd-Unit aktiviert `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` und einen unprivilegierten Benutzer. Prüfe vor dem Start, dass der Dienst die DNS-Logdatei lesen darf.

Das Repository ist privat angelegt. Keine API-Schlüssel, Zugangsdaten oder echten DNS-Logs gehören in das Repository. Nutze `.gitignore` für lokale Logs und generierte Dateien.
