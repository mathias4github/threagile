# Baseline (Phase 0a)

Stand: 2026-11-05, Branch `claude/modest-babbage-1pgomq` (statt `docs/baseline`, Vorgabe der Session), Basis `master` @ `a739b2a`.

## Toolchain
| | Version |
|---|---|
| `go.mod` | `go 1.26.0` |
| Session `go version` | go1.26.0 linux/amd64 |
| govulncheck | v1.9.0 (installiert in der Session) |

## Ergebnis auf unverändertem `master`: ROT
`go build ./...`, `go test ./...` und `go vet ./...` schlagen fehl:

```
go: golang.org/x/crypto@v0.45.0: missing go.sum entry for go.mod file
```

Ursache: `go.mod` ist nicht tidy – es nennt `x/crypto v0.45.0` / `x/text v0.31.0`, aber `go.sum`
enthält die Einträge für `v0.48.0` / `v0.34.0`, die eine Abhängigkeit ohnehin erzwingt. `go mod tidy`
ändert nur diese zwei Zeilen in `go.mod`, `go.sum` bleibt gleich.
Das ist ein Befund für Phase 0b (nicht hier gefixt, um 0a rein dokumentarisch zu halten).

**Messung daher mit getidyter go.mod-Kopie** (`-modfile`, bzw. Kopie des Repos für govulncheck), Repo unverändert:

| Befehl | Ergebnis |
|---|---|
| `go build ./...` | OK |
| `go test ./...` | OK (10 Pakete mit Tests, alle `ok`) |
| `go vet ./...` | OK, keine Meldungen |
| `govulncheck ./...` | **39 betreffende Schwachstellen** (siehe unten) |
| `go list -m -u all` | 67 Module mit Update (siehe unten) |
| `docker build .` | **nicht ausführbar**: in der Session kein Docker-Daemon |

Hinweise zum Dockerfile (statisch gelesen, nicht gebaut):
- Stage 1 klont `https://github.com/threagile/threagile.git` (Upstream-HEAD) statt den lokalen Quellstand zu kopieren – ein Docker-Build erfasst also **nicht** Änderungen dieses Forks.
- Base-Images ungepinnt (`alpine/git`, `golang`, `alpine`); `go test ./...` läuft im Build.
- Muss in Phase 0b auf einer Maschine mit Docker geprüft werden.

## govulncheck
Vollständige Ausgabe: `docs/baseline-govulncheck.txt`. Zusammenfassung:
- **Go-Standardbibliothek** (go1.26.0): Großteil der Findings (net/http, crypto/x509, html/template, net/url, os, …). Behoben mit **go1.26.10** (höchster „Fixed in“-Wert) – Toolchain-Anhebung in 0b löst sie.
- `golang.org/x/net` v0.51.0 → Fix ab v0.60.0 (4 Findings)
- `golang.org/x/text` v0.34.0 → Fix ab v0.39.0
- `github.com/xuri/excelize/v2` v2.9.0 → Fix ab v2.11.0 bzw. Pseudo-Version nach v2.11.1 (GO-2026-6688, GO-2026-6684 erst in einem Commit nach v2.11.1 behoben – ggf. nicht vollständig auflösbar)
- Zusätzlich 24 Findings in importierten Paketen und 29 in Modulen, deren verwundbarer Code nicht aufgerufen wird.

## Veraltete Module
Vollständige Liste (67): `docs/baseline-outdated-modules.txt`. Direkte Abhängigkeiten:

| Modul | aktuell | verfügbar | Sprung |
|---|---|---|---|
| github.com/gin-gonic/gin | v1.10.0 | v1.12.0 | Minor |
| github.com/spf13/cobra | v1.9.1 | v1.10.2 | Minor |
| github.com/xuri/excelize/v2 | v2.9.0 | v2.11.1 | Minor (CVE-relevant) |
| github.com/shopspring/decimal | v1.4.0 | v1.6.0 | Minor |
| github.com/mattn/go-shellwords | v1.0.12 | v1.0.16 | Patch |
| golang.org/x/crypto | v0.48.0 (go.mod: v0.45.0) | v0.58.0 | Minor |
| golang.org/x/text | v0.34.0 (go.mod: v0.31.0) | v0.43.0 | Minor |
| github.com/stretchr/testify | v1.10.0 | v1.12.1 | Minor |
| github.com/akedrou/textdiff | v0.0.0-2023… | v0.1.0 | Pseudo → Release |

**Kein Major-Sprung** (Pfad-Major-Wechsel) unter den direkten Abhängigkeiten verfügbar.
Aufgefallen: `jung-kurt/gofpdf` (v1.16.2), `wcharczuk/go-chart`, `mpvl/unique` sind unmaintained (keine Updates); `aws-sdk-go` und `golang/protobuf` sind als deprecated markiert (nur indirekt).

## Upstream-Test-Branches
`upstream-test-builtin-rules` und `upstream-test-script-engine` existieren in dieser Session **nicht** (weder lokal noch auf `origin`). Nichts zu prüfen.

## Golden Files
`test/golden/baseline/` (Rohdateien + `normalized/` + README). Erzeugt mit dem Beispielmodell
(`demo/example/threagile.yaml`; `create-example-model` kopiert es aus dem App-Dir) und
`analyze-model --keep-diagram-source-files`: 63 Risiken in 23 Kategorien, Stats siehe `stats.json`.

**Wichtig:** Die Ausgaben sind nicht deterministisch (Reihenfolge von Array-Elementen, z. B.
`data_breach_technical_assets`, sowie DOT-Zeilen und Excel-Zeilen). Rohvergleich ist daher unbrauchbar;
`scripts/golden-normalize.sh` normalisiert (Arrays sortieren, DOT sortieren, Excel-Strings sortieren).
Zwei Läufe hintereinander sind normalisiert identisch (geprüft). PNG/PDF/AsciiDoc wurden nicht aufgenommen.

## Offen
- `go.mod` nicht tidy → `master` baut nicht (siehe oben). Fix in 0b, Schritt 1.
- Nicht-deterministische Reihenfolge in JSON/DOT/Excel-Ausgabe (nur dokumentiert, nicht gefixt).
- Lauf endet mit Log-Zeile `logo image path does not exist: report/threagile-logo.png` (Exit-Code 0; Pfad relativ zum Arbeitsverzeichnis) – nur beobachtet.
- Dockerfile klont Upstream statt lokalem Stand; Docker-Build hier nicht verifizierbar.
