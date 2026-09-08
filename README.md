# Googlevideo-Blocklist-Fanger

Der **Googlevideo-Blocklist-Fanger** liest ausschließlich die offiziellen Query Logs von AdGuard DNS über einen persönlichen **AdGuard DNS API Key**. Gefundene `googlevideo.com`-Domains und Subdomains werden alle fünf Minuten in eine AdGuard-kompatible Blockliste geschrieben.

> **Festgelegte Integration:** Dieses Projekt verwendet bewusst **AdGuard DNS** und keinen selbst gehosteten AdGuard-Home-Server. AdGuard DNS unterstützt API-Key-Authentifizierung für die Query-Log-API. AdGuard Home verwendet für dieselbe Query-Log-Funktion derzeit HTTP Basic Auth und keine native API-Key-Authentifizierung.

## Datenquelle und Authentifizierung

Die einzige Datenquelle ist:

```text
GET https://api.adguard-dns.io/oapi/v1/query_log
```

Die Authentifizierung erfolgt ausschließlich mit:

```http
Authorization: ApiKey DEIN_API_KEY
```

Nicht unterstützt werden:

- lokale `dns.log`- oder Proxy-Logdateien,
- `--source` und `GV_SOURCE`,
- DNS-over-HTTPS-Zugangsdaten von `d.adguard-dns.com/dns-query`,
- Benutzername/Passwort in URLs,
- Bearer-Token.

> Ein DoH-Link löst DNS-Anfragen auf, stellt aber keine Query Logs bereit. DoH-Zugangsdaten sind kein AdGuard DNS API Key.

## Erkennung

Auf jedes von der API gelieferte `domain`-Feld wird dieser Regex angewandt:

```python
re.compile("(?i)(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*googlevideo\\.com(?![a-z0-9_.-])")
```

Erkannt werden beispielsweise:

```text
googlevideo.com
r1.googlevideo.com
r8.sn-w5nuxa-2tmz.googlevideo.com
rr3---sn-bvvbaxivnuxqjvhj5nu-qxo6.googlevideo.com
```

Die Ausgabe verwendet AdGuard-Syntax:

```text
||r8.sn-w5nuxa-2tmz.googlevideo.com^
```

## Installation auf Ubuntu/Debian

Repository nach `/opt` klonen oder aktualisieren:

```bash
cd /opt
sudo git clone https://github.com/Blacky1999/Googlevideo-Blocklist-Fanger.git
cd /opt/Googlevideo-Blocklist-Fanger
```

Falls es bereits vorhanden ist:

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo git pull origin main
```

Systembenutzer und Verzeichnisse anlegen:

```bash
sudo useradd --system --home /opt/Googlevideo-Blocklist-Fanger --shell /usr/sbin/nologin googlevideo-fanger 2>/dev/null || true
sudo install -d -o googlevideo-fanger -g googlevideo-fanger /var/lib/googlevideo-fanger
sudo touch /etc/googlevideo-fanger-allowlist.txt
sudo chown root:root /etc/googlevideo-fanger-allowlist.txt
sudo chmod 0644 /etc/googlevideo-fanger-allowlist.txt
```

## API Key sicher eintragen

Vorher im Chat, Terminalverlauf oder Repository veröffentlichte Schlüssel müssen im AdGuard-Konto widerrufen und ersetzt werden.

Vorlage installieren:

```bash
sudo install -m 0600 googlevideo-fanger.env.example /etc/googlevideo-fanger.env
sudo nano /etc/googlevideo-fanger.env
```

Inhalt:

```text
ADGUARD_DNS_API_KEY=DEIN_NEUER_ADGUARD_DNS_API_KEY
ADGUARD_DNS_LOOKBACK_SECONDS=86400
GV_INTERVAL=300
```

Die Datei muss nur für `root` lesbar bleiben:

```bash
sudo chown root:root /etc/googlevideo-fanger.env
sudo chmod 0600 /etc/googlevideo-fanger.env
```

Der API Key wird weder als Kommandozeilenargument noch im Repository gespeichert.

## Manueller Testlauf

Das Skript lädt `/etc/googlevideo-fanger.env` automatisch. Deshalb funktioniert auch ein Start mit `sudo`, ohne dass exportierte Benutzer-Variablen verloren gehen:

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo python3 googlevideo_fanger.py \
  --output /var/lib/googlevideo-fanger/googlevideo-blocklist.txt \
  --state /var/lib/googlevideo-fanger/state.json \
  --allowlist /etc/googlevideo-fanger-allowlist.txt \
  --once
```

Ergebnis prüfen:

```bash
sudo cat /var/lib/googlevideo-fanger/googlevideo-blocklist.txt
sudo cat /var/lib/googlevideo-fanger/state.json
```

Bei HTTP-Fehlern zeigt das Skript den von AdGuard gelieferten Fehlertext an. `401` oder `403` weist gewöhnlich auf einen ungültigen beziehungsweise unberechtigten API Key hin. `400` weist meist auf ungültige Abfrageparameter hin.

## Dauerbetrieb mit systemd

Unit installieren und starten:

```bash
cd /opt/Googlevideo-Blocklist-Fanger
sudo install -m 0644 googlevideo-fanger.service /etc/systemd/system/googlevideo-fanger.service
sudo systemctl daemon-reload
sudo systemctl enable --now googlevideo-fanger.service
```

Status und Logs:

```bash
sudo systemctl status googlevideo-fanger.service
sudo journalctl -u googlevideo-fanger.service -f
```

Die Unit lädt `/etc/googlevideo-fanger.env` und startet den API-Abruf alle 300 Sekunden. Die Blockliste liegt unter:

```text
/var/lib/googlevideo-fanger/googlevideo-blocklist.txt
```

## API-Abfrage

Jeder Zyklus sendet:

| Parameter | Wert |
|---|---|
| `time_from_millis` | Beginn des konfigurierten Zeitfensters |
| `time_to_millis` | aktuelle Zeit |
| `search` | `googlevideo.com` |
| `limit` | `1000` pro Seite |
| `cursor` | automatisch bei weiteren Seiten |

Das Standard-Zeitfenster beträgt 86.400 Sekunden beziehungsweise 24 Stunden. Pagination wird automatisch verarbeitet.

## Konfiguration

| Variable/Argument | Standard | Bedeutung |
|---|---:|---|
| `ADGUARD_DNS_API_KEY` | erforderlich | persönlicher AdGuard DNS API Key |
| `ADGUARD_DNS_LOOKBACK_SECONDS` / `--lookback-seconds` | `86400` | Query-Log-Zeitraum |
| `GV_INTERVAL` / `--interval` | `300` | Aktualisierungsintervall |
| `GV_OUTPUT` / `--output` | `./googlevideo-blocklist.txt` | Blocklist-Datei |
| `GV_STATE` / `--state` | `./googlevideo-state.json` | Statusdatei |
| `GV_ALLOWLIST` / `--allowlist` | `./allowlist.txt` | optionale Allowlist |
| `GV_ENV_FILE` / `--env-file` | `/etc/googlevideo-fanger.env` | geschützte Konfigurationsdatei |

## Tests

Die Tests verwenden ausschließlich simulierte API-Antworten und niemals einen echten Schlüssel:

```bash
python3 -m unittest -v
```

Geprüft werden Regex, alle 18 Beispieldomains, API-Key-Header, Pflichtzeitparameter, Pagination, Env-Datei, Allowlist und atomare Ausgabe.

## Sicherheit

- Keine Zugangsdaten in Git committen.
- `/etc/googlevideo-fanger.env` mit Modus `0600` schützen.
- Versehentlich veröffentlichte Keys sofort widerrufen.
- Die systemd-Unit läuft als unprivilegierter Benutzer und nutzt `NoNewPrivileges`, `ProtectSystem=strict` und `ProtectHome=true`.
- Das Blockieren von `googlevideo.com` kann YouTube und eingebettete Videos vollständig unterbrechen.

## Offizielle Dokumentation

- [AdGuard DNS API Reference](https://adguard-dns.io/kb/private-dns/api/reference/)
- [AdGuard DNS Query Log](https://adguard-dns.io/kb/private-dns/statistics-and-log/query-log/)
- [AdGuard DNS OpenAPI Specification](https://adguard-dns.io/api/swagger/openapi.json)
