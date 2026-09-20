# Googlevideo-Blocklist-Fanger

Der **Googlevideo-Blocklist-Fanger** liest alle fünf Minuten die Query Logs von **AdGuard DNS** mit einem persönlichen AdGuard-DNS-API-Key. Er erkennt `googlevideo.com` und passende Subdomains, erzeugt eine AdGuard-kompatible Blockliste und veröffentlicht sie automatisch im GitHub-Repository **[Blacky1999/Googlevideo-Blocklist-Fanger](https://github.com/Blacky1999/Googlevideo-Blocklist-Fanger)**.

> **Öffentliche Veröffentlichung:** Das Repository ist öffentlich. Jede neu erkannte Domain oder Subdomain wird nach erfolgreicher Synchronisierung in `googlevideo-blocklist.txt` öffentlich sichtbar. Die Synchronisierung wurde ausdrücklich für diese Veröffentlichung eingerichtet.

## Datenquellen und Authentifizierung

| Aufgabe | Dienst | Authentifizierung |
|---|---|---|
| Abfrage der DNS-Logs | `https://api.adguard-dns.io/oapi/v1/query_log` | `Authorization: ApiKey …` |
| Veröffentlichung der Blockliste | GitHub Contents API | `Authorization: Bearer …` mit einem GitHub Fine-grained Token |

Nicht verwendet werden lokale DNS-/Proxy-Logs, `dns-query`-URLs, DoH-Passwörter, Zugangsdaten in URLs oder AdGuard Home.

## Erkennung

Auf jedes `domain`-Feld der AdGuard-DNS-API wird dieser Regex angewandt:

```python
re.compile("Private Sorry”)
```

Damit werden beispielsweise erkannt:

```text
googlevideo.com
r1.googlevideo.com
r8.sn-w5nuxa-2tmz.googlevideo.com
rr3---sn-bvvbaxivnuxqjvhj5nu-qxo6.googlevideo.com
```

Die veröffentlichte Datei verwendet das AdGuard-Format:

```text
||r8.sn-w5nuxa-2tmz.googlevideo.com^
```

## Arbeitsweise

Bei jedem Zyklus führt das Tool folgende Schritte aus:

1. Es fragt die AdGuard-DNS-Query-Log-API mit `search=googlevideo.com` ab.
2. Es verwendet ein konfigurierbares Zeitfenster, standardmäßig die letzten 24 Stunden, und verarbeitet bei Bedarf weitere API-Seiten.
3. Es wendet den Regex an, normalisiert und dedupliziert Hosts und entfernt optionale Allowlist-Einträge.
4. Es schreibt die vollständige Blockliste atomar lokal.
5. Es liest `googlevideo-blocklist.txt` aus dem GitHub-Repository.
6. Es erstellt **nur bei verändertem Inhalt** einen GitHub-Commit und ersetzt die Datei über die Contents API.

Unveränderte Blocklisten erzeugen keinen Commit. Bei einem API- oder GitHub-Fehler wird keine erfolgreiche Synchronisierung im Status gespeichert.

## Installation auf Ubuntu/Debian

```bash
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/Blacky1999/Googlevideo-Blocklist-Fanger.git
cd /opt/Googlevideo-Blocklist-Fanger

sudo useradd --system --home /opt/Googlevideo-Blocklist-Fanger \
  --shell /usr/sbin/nologin googlevideo-fanger 2>/dev/null || true
sudo install -d -o googlevideo-fanger -g googlevideo-fanger /var/lib/googlevideo-fanger
sudo touch /etc/googlevideo-fanger-allowlist.txt
sudo chown root:root /etc/googlevideo-fanger-allowlist.txt
sudo chmod 0644 /etc/googlevideo-fanger-allowlist.txt
```

Bereits vorhandene Installation aktualisieren:

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo git pull --ff-only origin main
```

## Schlüssel sicher hinterlegen

Erstelle im GitHub-Konto einen **Fine-grained Personal Access Token** mit Zugriff nur auf `Blacky1999/Googlevideo-Blocklist-Fanger` und Berechtigung **Contents: Read and write**. Dieser Token ist notwendig, damit der Dienst die öffentliche Datei aktualisieren kann.

Die Konfigurationsdatei wird ausschließlich für `root` lesbar angelegt:

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo install -m 0600 googlevideo-fanger.env.example /etc/googlevideo-fanger.env
sudo nano /etc/googlevideo-fanger.env
```

Beispielinhalt:

```text
ADGUARD_DNS_API_KEY=DEIN_NEUER_ADGUARD_DNS_API_KEY
GITHUB_TOKEN=DEIN_GITHUB_FINE_GRAINED_TOKEN
GITHUB_REPOSITORY=Blacky1999/Googlevideo-Blocklist-Fanger
GITHUB_BRANCH=main
GITHUB_BLOCKLIST_PATH=googlevideo-blocklist.txt
ADGUARD_DNS_LOOKBACK_SECONDS=86400
GV_INTERVAL=300
GV_LOG_LEVEL=INFO
```

Dateirechte nochmals prüfen:

```bash
sudo chown root:root /etc/googlevideo-fanger.env
sudo chmod 0600 /etc/googlevideo-fanger.env
```

> API-Keys und GitHub-Tokens gehören niemals in Git, Kommandozeilenargumente oder Logs. Vorher versehentlich veröffentlichte Zugangsdaten müssen widerrufen und ersetzt werden.

## Manueller Testlauf

Das Skript liest `/etc/googlevideo-fanger.env` automatisch, auch beim Start mit `sudo`:

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo python3 googlevideo_fanger.py \
  --output /var/lib/googlevideo-fanger/googlevideo-blocklist.txt \
  --state /var/lib/googlevideo-fanger/state.json \
  --allowlist /etc/googlevideo-fanger-allowlist.txt \
  --once
```

Lokale Ausgabe und veröffentlichte Datei prüfen:

```bash
sudo cat /var/lib/googlevideo-fanger/googlevideo-blocklist.txt
sudo cat /var/lib/googlevideo-fanger/state.json
curl -fsSL https://raw.githubusercontent.com/Blacky1999/Googlevideo-Blocklist-Fanger/main/googlevideo-blocklist.txt
```

## Dauerbetrieb mit systemd

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo install -m 0644 googlevideo-fanger.service /etc/systemd/system/googlevideo-fanger.service
sudo systemctl daemon-reload
sudo systemctl enable --now googlevideo-fanger.service
sudo systemctl restart googlevideo-fanger.service
```

Status und Live-Logs:

```bash
sudo systemctl status googlevideo-fanger.service
sudo journalctl -u googlevideo-fanger.service -f
```

Die lokale Arbeitskopie wird unter folgendem Pfad geschrieben:

```text
/var/lib/googlevideo-fanger/googlevideo-blocklist.txt
```

Die veröffentlichte Blockliste liegt im Standardfall hier:

```text
https://raw.githubusercontent.com/Blacky1999/Googlevideo-Blocklist-Fanger/main/googlevideo-blocklist.txt
```

## Konfiguration

| Variable/Argument | Standard | Bedeutung |
|---|---:|---|
| `ADGUARD_DNS_API_KEY` | erforderlich | persönlicher AdGuard-DNS-API-Key |
| `GITHUB_TOKEN` | erforderlich | Fine-grained Token mit `Contents: Read and write` |
| `GITHUB_REPOSITORY` / `--github-repository` | `Blacky1999/Googlevideo-Blocklist-Fanger` | öffentliches Ziel-Repository |
| `GITHUB_BRANCH` / `--github-branch` | `main` | Ziel-Branch |
| `GITHUB_BLOCKLIST_PATH` / `--github-blocklist-path` | `googlevideo-blocklist.txt` | Repository-Pfad der veröffentlichten Liste |
| `ADGUARD_DNS_LOOKBACK_SECONDS` / `--lookback-seconds` | `86400` | Zeitfenster der Query-Logs |
| `GV_INTERVAL` / `--interval` | `300` | Aktualisierungsintervall in Sekunden |
| `GV_OUTPUT` / `--output` | `./googlevideo-blocklist.txt` | lokale Arbeitskopie |
| `GV_STATE` / `--state` | `./googlevideo-state.json` | Status, Hash und GitHub-Ergebnis |
| `GV_ALLOWLIST` / `--allowlist` | `./allowlist.txt` | optionale erlaubte Hosts |
| `GV_ENV_FILE` / `--env-file` | `/etc/googlevideo-fanger.env` | geschützte Konfigurationsdatei |

## Tests

Die Tests benötigen keinen echten API-Key oder GitHub-Token:

```bash
python3 -m unittest -v
```

Getestet werden der Regex mit 18 Beispieldomains, AdGuard-Authentifizierung, Zeitfenster, Pagination, GitHub-Update mit SHA, die Unterdrückung identischer Updates, Env-Datei, Allowlist und Statusdatei.

## Sicherheit und Grenzen

- Der Dienst läuft über systemd mit einem unprivilegierten Benutzer und `NoNewPrivileges`, `ProtectSystem=strict` und `ProtectHome=true`.
- Die GitHub-Synchronisierung veröffentlicht alle enthaltenen Hosts im öffentlichen Repository.
- Ein API-Key oder Token mit zu umfangreichen Rechten erhöht das Risiko; der GitHub-Token sollte ausschließlich auf dieses Repository begrenzt sein.
- Das Blockieren von `googlevideo.com` kann YouTube und eingebettete Videos beeinträchtigen oder vollständig unterbrechen.

## Offizielle Dokumentation

- [AdGuard DNS API Reference](https://adguard-dns.io/kb/private-dns/api/reference/)
- [AdGuard DNS Query Log](https://adguard-dns.io/kb/private-dns/statistics-and-log/query-log/)
- [GitHub: Create or update file contents](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents)
