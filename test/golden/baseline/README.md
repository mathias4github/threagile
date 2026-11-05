# Golden Baseline

Referenzausgabe des Beispielmodells (`demo/example/threagile.yaml`) auf dem aktuellen `master`.
Erzeugt mit `analyze-model --keep-diagram-source-files`, App-Dir wie im Docker-Image.

Prüfen bzw. neu erzeugen (benötigt `go`, `jq`, `unzip`, Graphviz):

```bash
scripts/golden-run.sh            # Vergleich, Exit-Code 1 bei Abweichung
scripts/golden-run.sh --update   # Baseline neu schreiben (nur bei erklärter Abweichung)
```

Die Rohdateien sind zwischen Läufen NICHT byte-identisch (Reihenfolge von Array-Elementen,
DOT- und Excel-Zeilen schwankt). Maßgeblich ist daher `normalized/` (erzeugt von
`scripts/golden-normalize.sh`); zwei Läufe hintereinander sind normalisiert identisch.

## Historie
| Stand | Risiken | Änderung |
|---|---|---|
| Phase 0a | 63 | Ausgangsstand |
| Fix #130 | 65 | Custom-Risiken des Beispielmodells (`something-strange`) erscheinen |
| Fix #96 | 65 | Feld `cwe` in `risks.json` |
| Phase 2 (pytm-Regeln) | 68 | +2 `http-request-smuggling`, +1 `xml-entity-expansion-dos` |
| Review-Fixes | 68 | Titel von `http-request-smuggling` ohne Forwarder-Namen |
| Regel-Review | 68 | `xml-entity-expansion-dos`: CWE 776 → 770 |
