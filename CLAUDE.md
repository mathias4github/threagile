# Threagile – Renovierung und pytm-Regelportierung

## Kontext
Dieses Repo ist der Fork `mathias4github/threagile` von `Threagile/threagile`.
Hauptbranch ist `master`. Es gibt KEIN zweites Repo und KEIN upstream-Remote
in der Session. Alles, was du brauchst, liegt hier:
- `docs/reference/pytm-threats.json` – Snapshot von OWASP pytm
  `threatlib/threats.json`; `docs/reference/pytm-pytm.py` erklärt die
  Element-Attribute (Lizenz in `docs/reference/pytm-LICENSE`).
- `docs/reference/upstream-issues.json` – Export der offenen Issues des
  Upstream-Repos. `gh issue` und `gh pr` funktionieren hier nicht; nutze
  diese Datei und für Lesezugriffe sonst `gh api repos/mathias4github/threagile/...`.
- Branches `upstream-test-builtin-rules` und `upstream-test-script-engine`
  (falls vorhanden): Kopien offener Upstream-Branches mit Tests.

Ziele in dieser Reihenfolge:
1. Threagile baut sauber auf aktueller Toolchain, Abhängigkeiten aktuell,
   keine offenen CVEs, bekannte Bugs mit Test gefixt (Phase 0).
2. Neue Go-Built-in-Regeln, portiert aus pytm, PR-fähig (Phase 1–3).

## Arbeitsweise – zwingend
- Du läufst in einer Cloud-Session. Jede Phase hat ihre eigene Session; lies
  am Start nur CLAUDE.md und das Übergabe-Dokument der aktuellen Phase.
- An jedem markierten STOPP anhalten, Ergebnis zusammenfassen und auf
  Freigabe warten.
- Jede Phase hat einen eigenen Branch. Nie Änderungen verschiedener Phasen in
  einem Branch mischen. Nie auf `master` committen.
- Pushen ist erlaubt und erwünscht: nach jedem STOPP den Phasen-Branch
  pushen, damit der Stand sichtbar ist. Keine Pull Requests erstellen – das
  macht der Mensch aus der Session heraus.
- Jeder Commit lässt `go build ./... && go test ./...` grün.
- Commit-Format: `<typ>(<bereich>): <beschreibung>` –
  Typen: `chore`, `fix`, `feat`, `test`, `docs`, `ci`.
- Bugs, die während einer späteren Phase auffallen, werden NICHT dort gefixt,
  sondern in `docs/baseline.md` unter „Offen" notiert.
- Lange Befehle (go mod download, docker build) im Hintergrund laufen lassen
  und auf das Ergebnis warten, nicht abbrechen.

---

## Phase 0a – Baseline erfassen (Branch: docs/baseline)
1. Go-Version aus `go.mod` notieren; `go version` der Session notieren.
2. Ausführen und Ergebnisse festhalten:
   `go build ./...`, `go test ./...`, `go vet ./...`,
   `govulncheck ./...`, `go list -m -u all`, `docker build .`
3. Falls die Branches `upstream-test-builtin-rules` und
   `upstream-test-script-engine` existieren: prüfen, ob ihr Inhalt bereits
   in `master` ist (`git log master..<branch>`). Wenn nicht: in
   `docs/baseline.md` festhalten, was sie enthalten und ob ein Merge in
   Phase 0b sinnvoll wäre. Nicht mergen.
4. Golden Files erzeugen: Beispielmodell mit `--create-example-model`
   anlegen, vollständigen Lauf ausführen, Ausgaben (risks.json, stats.json,
   technical-assets.json, Excel, DFD-DOT) nach `test/golden/baseline/`
   kopieren. Diese Dateien sind das Referenzergebnis für alle Folgeschritte.
5. Schreibe `docs/baseline.md`: Toolchain-Stand, Testergebnis, Liste
   veralteter Module (aktuelle vs. verfügbare Version, Major-Sprung
   markieren), CVE-Liste aus govulncheck, Docker-Build-Status.
6. Commit, Push.
STOPP. Freigabe abwarten.

## Phase 0b – Abhängigkeiten und Toolchain (Branch: chore/deps-2026)
Basis: `master` nach Merge von Phase 0a.
Nach JEDEM Schritt: Build, Test, Beispielmodell neu laufen lassen und
Ausgaben gegen `test/golden/baseline/` diffen. Unterschiede in Risiken,
Assets oder Statistiken sind ein Fehler und müssen erklärt oder behoben
werden, bevor es weitergeht. Zeitstempel und Versionsstrings ignorieren.

1. Go-Version in `go.mod` auf aktuelle stabile Version anheben,
   `go mod tidy`. Commit.
2. Alle Minor-/Patch-Updates auf einmal: `go get -u ./...`, `go mod tidy`.
   Commit.
3. Major-Updates EINZELN, je eigener Commit, Reihenfolge: zuerst Module mit
   wenig Nutzung, zuletzt Gin, Cobra, YAML-, Excel- und PDF-Bibliothek.
   Bei API-Bruch: anpassen, wenn überschaubar; sonst Modul auf alter Major-
   Version belassen und in `docs/baseline.md` unter „Zurückgestellt"
   begründen.
4. `govulncheck ./...` erneut. Ziel: keine offenen Findings. Rest
   dokumentieren.
5. Dockerfile: Base-Images auf aktuelle Tags, Multi-Stage prüfen,
   `docker build .` muss laufen, Container mit Beispielmodell testen.
6. GitHub-Actions-Workflows: Action-Versionen anheben, `setup-go` auf die
   Version aus `go.mod` angleichen.
7. `docs/baseline.md` aktualisieren: was angehoben wurde, was zurückgestellt
   ist und warum.
8. PR-Beschreibung in `docs/PR-deps.md`: Zusammenfassung, Liste der
   Major-Sprünge mit nötigen Code-Anpassungen, Golden-Diff-Ergebnis.
9. Commit, Push.
STOPP. Freigabe abwarten. Fork-Tag und Docker-Image sind Sache des Menschen.

## Phase 0c – Bugs (Branch je Bug: fix/<issue-nr>-<kurzname>)
Basis: `master` nach Merge von Phase 0b.

1. Triage (Branch: docs/bug-triage): alle Einträge aus
   `docs/reference/upstream-issues.json` lesen und in `docs/bug-triage.md`
   einsortieren:
   - REPRODUZIERBAR: Fehlverhalten ist mit einem Minimal-Modell oder
     Unit-Test nachstellbar.
   - DOKU/USABILITY: kein Fehlverhalten, nur unklar oder unbequem.
   - FEATURE: Wunsch nach neuer Funktion.
   - UNKLAR: nicht genug Information.
   Nur REPRODUZIERBAR wird bearbeitet. Priorisierte Liste vorschlagen.
   Commit, Push.
STOPP. Freigabe abwarten.

2. Je freigegebenem Bug, in eigener Session und eigenem Branch:
   a. Test schreiben, der den Bug zeigt. Test muss ROT sein. Commit
      `test(...)`.
   b. Fix implementieren. Test muss GRÜN sein, alle anderen Tests ebenfalls.
      Commit `fix(...)`.
   c. Golden-Diff gegen Baseline. Abweichungen nur zulässig, wenn sie
      direkt aus dem Fix folgen – dann in `docs/bug-triage.md` erklären.
   d. PR-Text in `docs/PR-fix-<issue-nr>.md`: Symptom, Ursache, Fix, Test.
   e. Push.
   Kein Fix ohne Test. Kein Refactoring über den Fix hinaus.
STOPP nach jedem Bug. Freigabe abwarten.

---

## Phase 1 – Lückenanalyse pytm → Threagile (Branch: feature/pytm-ported-rules)
Basis: `master` nach Merge von Phase 0b und der Fixes.

1. Lies alle Built-in-Regeln in diesem Repo (Regelverzeichnis lokalisieren,
   IDs und Bedingungen zusammenfassen).
2. Lies `docs/reference/pytm-threats.json` vollständig; schlage Attribute
   bei Bedarf in `docs/reference/pytm-pytm.py` nach.
3. Erstelle `docs/pytm-mapping.md` mit allen pytm-SIDs:
   SID | Titel | Status | Threagile-Pendant | Begründung |
   geplante Bedingung in Threagile-Begriffen.
   Status ist eines von:
   - ABGEDECKT (Threagile-Regel existiert, ID nennen)
   - PORTIERBAR (Bedingung mit Threagile-Datenmodell ausdrückbar:
     Technologie-Typ, Protokoll, Trust Boundary, Data-Asset-CIA, Tags)
   - TAG-BASIERT (nur abbildbar, wenn Modellierer ein Tag setzt –
     Tag-Namen vorschlagen)
   - NICHT ABBILDBAR (pytm-Attribut ohne Entsprechung)
4. Markiere pytm-Regeln mit fehlerhaften Bedingungen (z. B. Attribute, die
   für den Zieltyp nicht existieren).
5. Priorisierte Liste der PORTIERBAR-Regeln, maximal 25.
6. Commit, Push.
STOPP. Freigabe abwarten.

## Phase 2 – Implementierung der Regeln (gleicher Branch)
Nur freigegebene Regeln, Reihenfolge wie in der Freigabe.
- Bestehende Threagile-Regeln nicht verändern. Nur neue hinzufügen.
- Keine Texte aus pytm wörtlich übernehmen. Beschreibung, Mitigation und
  Referenzen (CWE/CAPEC/OWASP) in eigenen Worten im Stil der bestehenden
  Regeln formulieren.
- Je Regel: Go-Datei nach dem Muster EINER bestehenden Regel gleicher Art
  (nur diese eine Vorlage lesen, nicht das ganze Verzeichnis), Unit-Test mit
  Positiv- und Negativfall, Eintrag in der Regel-Registrierung, Build, Test,
  Commit `feat(rules): add <rule-id> (ported from pytm <SID>)`.
- Nach je 5 Regeln: Beispielmodell laufen lassen, keine Panics, neue Regeln
  erscheinen im JSON-Output, wo das Modell sie triggern sollte. Golden-Diff:
  nur Zusätze durch neue Regeln erlaubt, keine Änderung bestehender Risiken.
  Dann Push und kurzer Zwischenstand – aber NICHT auf Freigabe warten,
  weiterarbeiten.
- Am Ende: Kurzbericht in `docs/pytm-mapping.md`, welche Regeln auf dem
  Beispielmodell anschlagen. Push.
STOPP. Freigabe abwarten.

## Phase 3 – PR-Vorbereitung Regeln (gleicher Branch)
- `go vet ./...`, `gofmt` über alle neuen Dateien.
- `docs/pytm-mapping.md` finalisieren.
- `docs/PR-rules.md`: Motivation, Liste der Regeln mit Kurzbegründung,
  Hinweis auf Tests, Hinweis auf Herkunft (OWASP pytm, permissive Lizenz).
- Keine Änderung an README oder Versionsnummer.
- Commit, Push.

---

## Definition of Done
- Phase 0: Build, Test, Vet grün; govulncheck ohne offene Findings oder
  dokumentiert; Docker-Build läuft; Golden-Diff erklärt; jeder Bugfix hat
  einen vorher roten Test.
- Phase 1–3: jede neue Regel hat Positiv- und Negativtest; Mapping-Dokument
  vollständig; Golden-Diff zeigt nur Zusätze; Branch gepusht.
