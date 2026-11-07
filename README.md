## Sicherheit und Grenzen

- Der Dienst läuft über systemd mit einem unprivilegierten Benutzer und `NoNewPrivileges`, `ProtectSystem=strict` und `ProtectHome=true`.
- Die GitHub-Synchronisierung veröffentlicht alle enthaltenen Hosts im öffentlichen Repository.
- Ein API-Key oder Token mit zu umfangreichen Rechten erhöht das Risiko; der GitHub-Token sollte ausschließlich auf dieses Repository begrenzt sein.
- Das Blockieren von `googlevideo.com` kann YouTube und eingebettete Videos beeinträchtigen oder vollständig unterbrechen.

## Offizielle Dokumentation

N/A
