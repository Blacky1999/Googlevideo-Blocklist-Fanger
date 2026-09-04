# Googlevideo-Blocklist-Fanger

Ein kleiner, serverfähiger Python-Dienst, der eine lokale DNS- oder Proxy-Logdatei nach `googlevideo.com`-Domains und Subdomains durchsucht und daraus alle fünf Minuten eine **AdGuard-kompatible Blockliste** erzeugt.

## Was der Dienst macht

Der Fänger liest ausschließlich eine von dir angegebene lokale Quelldatei. Die Erkennung verwendet genau diesen einzeiligen Python-Regex:

```python
re.compile(r"(?i)(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*googlevideo\.com(?![a-z0-9_.-])")
```

Aus einer Zeile wie `query r1---sn-ab5l6n7e.googlevideo.com` wird ausschließlich der vollständige Treffer `r1---sn-ab5l6n7e.googlevideo.com` übernommen. Der Fänger dedupliziert Treffer, entfernt optionale Allowlist-Einträge und schreibt die Blockliste atomar. Dadurch lesen DNS-/AdGuard-Clients entweder die alte oder die vollständige neue Datei, niemals eine halbfertige Datei.

Der Dienst lädt keine fremden Blocklisten, ruft keine externen APIs auf und leitet keine DNS-Daten weiter. Die Blockliste ist kumulativ über den aktuellen Inhalt der Logdatei; bei Logrotation sollte die Quelldatei auf den aktiven Logpfad zeigen.

> Hinweis: Eine Blockliste für `googlevideo.com` kann YouTube-Videoauslieferung, eingebettete Videos und andere Google-Video-Dienste beeinträchtigen. Nutze die Allowlist für benötigte Hosts.

## Schnelltest

```bash
python3 -m unittest -v
printf '%s\n' 'r1---sn-ab5l6n7e.googlevideo.com query' > dns.log
python3 googlevideo_fanger.py --source dns.log --output googlevideo-blocklist.txt --state state.json --once
cat googlevideo-blocklist.txt
```

## Serverbetrieb mit systemd

Die mitgelieferte Unit erwartet einen Debian-/Ubuntu-Server und eine DNSMasq-Logdatei unter `/var/log/dnsmasq.log`. Passe den Pfad in `googlevideo-fanger.service` an, falls dein DNS- oder Proxy-Dienst an eine andere Datei schreibt.

```bash
sudo useradd --system --home /opt/googlevideo-blocklist-fanger --shell /usr/sbin/nologin googlevideo-fanger
sudo install -d -o googlevideo-fanger -g googlevideo-fanger /opt/googlevideo-blocklist-fanger /var/lib/googlevideo-fanger
sudo install -m 0755 googlevideo_fanger.py /opt/googlevideo-blocklist-fanger/googlevideo_fanger.py
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
| `--source` / `GV_SOURCE` | `./dns.log` | lokale DNS-/Proxy-Logdatei |
| `--output` / `GV_OUTPUT` | `./googlevideo-blocklist.txt` | AdGuard-Ausgabe |
| `--state` / `GV_STATE` | `./googlevideo-state.json` | Status und Hash |
| `--allowlist` / `GV_ALLOWLIST` | `./allowlist.txt` | erlaubte googlevideo-Hosts, eine Domain pro Zeile |
| `--interval` / `GV_INTERVAL` | `300` | Aktualisierungsintervall in Sekunden |

Das Mindestintervall beträgt 30 Sekunden. Für die gewünschte Aktualisierung alle fünf Minuten bleibt der systemd-Wert `300`.

## Sicherheit und Grenzen

Der Dienst benötigt nur Leserechte auf die Quelldatei und Schreibrechte auf sein Ausgabeverzeichnis. Die systemd-Unit aktiviert `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` und einen unprivilegierten Benutzer. Prüfe vor dem Start, dass der Dienst die DNS-Logdatei lesen darf.

Das Repository ist privat angelegt. Keine API-Schlüssel, Zugangsdaten oder echten DNS-Logs gehören in das Repository. Nutze `.gitignore` für lokale Logs und generierte Dateien.
