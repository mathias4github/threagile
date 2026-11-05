# fix(report): add `cwe` to risks.json (#96)

**Symptom:** `risks.xlsx` hat eine CWE-Spalte, `risks.json` enthält die CWE nicht.

**Ursache:** Zwei getrennte Code-Pfade; der JSON-Export serialisiert `types.Risk`, das keine CWE trägt (sie hängt an der Kategorie).

**Fix:** `pkg/report/json.go`: `WriteRisksJSON` ergänzt pro Risiko `cwe` aus der Risikokategorie (`omitempty`). `types.Risk` bleibt unverändert.

**Test:** `pkg/report/json_test.go` – Kategorie mit/ohne CWE; vor dem Fix rot, danach grün.

**Golden-Diff:** nur das Zusatzfeld `cwe` in `risks.json`.
