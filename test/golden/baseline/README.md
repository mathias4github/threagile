# Golden Baseline

Referenzausgabe von `master` (Stand Phase 0a) für das Beispielmodell (`demo/example/threagile.yaml`).
Erzeugt mit `analyze-model --keep-diagram-source-files`, App-Dir wie im Docker-Image.

Die Rohdateien sind zwischen Läufen NICHT byte-identisch (Reihenfolge von Array-Elementen und
DOT-Zeilen schwankt). Vergleich daher immer normalisiert:

```bash
scripts/golden-normalize.sh <ausgabeverzeichnis> /tmp/golden-new
diff -r test/golden/baseline/normalized /tmp/golden-new
```

Zwei Läufe hintereinander ergeben normalisiert identische Ausgaben (geprüft).
`normalized/` ist das maßgebliche Referenzergebnis. Erwartet: 63 Risiken (siehe stats.json).
Benötigt `jq`, `unzip`.
