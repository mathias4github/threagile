# fix(input): accept legacy `individual_risk_categories` (#130)

**Symptom:** Custom-Risiken aus dem mitgelieferten Beispielmodell (`demo/example`) und dem Stub erscheinen nicht in Report/JSON; kein Fehler, keine Warnung.

**Ursache:** Der Parser liest nur `custom_risk_categories` (Liste). Beispiel, Stub, Server-Template und Schema nutzten weiter `individual_risk_categories` (Map nach Titel); die Umbenennung hatte keine Kompatibilität.

**Fix:** `pkg/input/model.go`: der alte Schlüssel (Map nach Titel oder Liste) wird in `CustomRiskCategories` übernommen (auch in `includes`), mit Deprecation-Warnung. Beispiel, Stub, Server-Template nutzen den neuen Schlüssel; `schema.json` kennt `custom_risk_categories` und markiert den alten als deprecated.

**Test:** `pkg/input/model_legacy_risk_categories_test.go` (Load, Include, unveränderter neuer Schlüssel) – vor dem Fix rot, danach grün.

**Golden-Diff:** Die zwei Risiken von `something-strange` erscheinen erstmals (Stats, Excel, Data-Asset-Diagramm-Farbe der Datenbank); alle übrigen Ergebnisse identisch. Details: `docs/bug-triage.md`.

Nebenbei: `.gitignore` versteckte Teile der Golden-Baseline (`!/test/golden/**`).
