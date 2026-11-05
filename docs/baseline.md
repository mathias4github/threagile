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
`upstream-test-builtin-rules` und `upstream-test-script-engine` waren in der Session zunächst nicht sichtbar und
tauchten erst nach `git fetch origin` auf (ebenso `test/builtin-rule-unit-tests`, `test/script-engine-unit-tests`).
`git log master..origin/<branch>` ist für alle vier **leer**: der Inhalt ist bereits in `master`. Kein Merge nötig.
(Korrektur: die erste Fassung dieses Dokuments behauptete fälschlich, die Branches existierten nicht.)

## Golden Files
`test/golden/baseline/` (Rohdateien + `normalized/` + README). Erzeugt mit dem Beispielmodell
(`demo/example/threagile.yaml`; `create-example-model` kopiert es aus dem App-Dir) und
`analyze-model --keep-diagram-source-files`: 63 Risiken in 23 Kategorien, Stats siehe `stats.json`.

**Wichtig:** Die Ausgaben sind nicht deterministisch (Reihenfolge von Array-Elementen, z. B.
`data_breach_technical_assets`, sowie DOT-Zeilen und Excel-Zeilen). Rohvergleich ist daher unbrauchbar;
`scripts/golden-normalize.sh` normalisiert (Arrays sortieren, DOT sortieren, Excel-Strings sortieren).
Zwei Läufe hintereinander sind normalisiert identisch (geprüft). PNG/PDF/AsciiDoc wurden nicht aufgenommen.

## Offen
- ~~`go.mod` nicht tidy → `master` baut nicht~~ – behoben in Phase 0b.
- ~~Dockerfile klont Upstream statt lokalem Stand~~ – behoben in Phase 0b; `docker build` weiterhin **nicht verifiziert** (kein Docker-Daemon in den Sessions).
- Nicht-deterministische Reihenfolge in JSON/DOT/Excel-Ausgabe (Map-Iteration, z. B. `pkg/model/parse.go:233`) – nur dokumentiert; Golden-Vergleich daher normalisiert.
- Lauf endet mit Log-Zeile `logo image path does not exist: report/threagile-logo.png` (Exit-Code 0; Pfad relativ zum Arbeitsverzeichnis) – nur beobachtet.
- `risks.json`: Risiken mit Severity `low` haben kein Feld `severity` (`omitempty` auf Enum-Wert 0 in `pkg/types/risk.go`); im Beispielmodell 5 Risiken. Kandidat für einen eigenen Fix (Verhaltensänderung des JSON-Formats).
- Server-Modus (`pkg/server/model.go`, `readModel`) parst Modelle direkt per `yaml.Unmarshal`, nicht über `input.Model.Load`: der Legacy-Schlüssel `individual_risk_categories` bleibt beim Speichern erhalten, wird in den Server-Listen der Custom-Kategorien aber nicht angezeigt (Analyse über `Load` übernimmt ihn).
- `server/static/js/edit-model.js` und `support/live-templates.txt` erzeugen noch `individual_risk_categories` (wird dank #130-Fix gelesen, erzeugt aber eine Deprecation-Warnung).
- Script-Engine (`pkg/risks/script/script.go`) nutzt intern weiterhin den Schlüssel `individual_risk_categories` (eigenes Format, nicht vom #130-Fix betroffen).

---

# Phase 0b – Ergebnis (Dependencies/Toolchain)

## Angehoben
- `go.mod`: tidy (master baute vorher nicht), `go 1.26.0` → `go 1.27.3` (aktuelle stabile Version laut go.dev).
- Alle Minor/Patch-Updates via `go get -u ./...` (u. a. gin 1.12.0, cobra 1.10.2, excelize 2.11.1, x/crypto 0.58.0, x/net 0.62.0, x/text 0.43.0).
- Dockerfile: `golang:1.27`, `alpine:3.23` gepinnt; Clone-Stage entfernt, es wird der lokale Quellstand gebaut.
- Nach jedem Schritt: Build, Test, Beispielmodell, normalisierter Golden-Diff → jeweils **GOLDEN OK** (keine Abweichung bei Risiken, Assets, Stats, DOT, Excel).

## govulncheck danach
„Your code is affected by 0 vulnerabilities“ (Vorher: 39). Vollständige Ausgabe: `docs/deps-govulncheck-after.txt`.
Rest: GO-2026-5932 (`x/crypto/openpgp`, unmaintained) – Modul wird required, das Paket aber nicht importiert/aufgerufen; kein Fix verfügbar.

## Major-Updates
Unter den direkten Abhängigkeiten gab es **keinen** verfügbaren Major-Sprung (Pfad-Major); daher keine Einzel-Commits nötig.

## Zurückgestellt
- Verbleibende Updates in `docs/deps-outdated-after.txt` sind ausschließlich indirekte Module (u. a. jackc/pgx v4, dd-trace-go v1, grpc, aws-sdk-go) – von transitiven, teils unmaintainten Abhängigkeiten festgehalten (go-chart-Umfeld); kein Direkt-Update möglich ohne Ersatz der Bibliothek.
- `gopkg.in/yaml.v3` ist archiviert; Nachfolger `go.yaml.in/yaml/v3` (liegt bereits indirekt im Graph). Migration wäre ein Import-Wechsel im ganzen Repo → eigene Entscheidung, nicht in 0b.
- `jung-kurt/gofpdf`, `wcharczuk/go-chart`, `mpvl/unique`: unmaintained, keine Updates.
- GitHub-Actions-Versionen (`checkout@v4`, `setup-go@v5`, `codeql-action@v4`, `golangci-lint-action@v8` usw.): **nicht angehoben**, da neue Tags in dieser Session nicht abfragbar waren (kein Zugriff auf die Action-Repos). `setup-go` nutzt bereits `go-version-file: go.mod`, ist also mit go.mod synchron.
- `docker build .` und Container-Test mit Beispielmodell: **nicht ausgeführt** (kein Docker-Daemon). Dockerfile-Änderung ist ungetestet. Als Ersatz wurde die Binary mit App-Dir-Layout wie im Image gegen das Beispielmodell geprüft.
