# chore(deps): Go 1.27.3 und Abhängigkeiten aktualisieren

## Zusammenfassung
- `master` baute nicht (nicht-tidy `go.mod`, fehlender go.sum-Eintrag x/crypto v0.45.0) → behoben.
- Go-Direktive auf 1.27.3; alle Minor/Patch-Updates (`go get -u ./...`).
- govulncheck: 39 → **0** betroffene Schwachstellen.
- Dockerfile: Base-Images gepinnt, lokaler Quellstand statt Upstream-Clone.

## Major-Sprünge
Keine verfügbar bei direkten Abhängigkeiten; keine Code-Anpassungen nötig (nur `go.mod`/`go.sum`/`Dockerfile`).

## Golden-Diff
Nach jedem Commit gegen `test/golden/baseline/normalized` (`scripts/golden-normalize.sh`): **identisch** – 63 Risiken, Assets, Stats, DOT und Excel unverändert.

## Nicht geprüft / zurückgestellt
- `docker build` (kein Daemon in der Session) – bitte lokal oder per CI prüfen.
- GitHub-Actions-Versionen unverändert (Tags nicht abfragbar).
- Details: `docs/baseline.md`, Abschnitt „Phase 0b“.

Commits: tidy-Fix, Go 1.27.3, Dependencies, Docker, Doku.
