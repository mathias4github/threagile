#!/usr/bin/env bash
# Normalisiert Threagile-Ausgaben für Golden-Diffs (Reihenfolge von Arrays/Zeilen ist nicht deterministisch).
# Aufruf: scripts/golden-normalize.sh <ausgabeverzeichnis> <zielverzeichnis>
set -euo pipefail
in=$1; out=$2; mkdir -p "$out"
for f in risks stats technical-assets; do
  jq -S 'walk(if type=="array" then sort_by(tostring) else . end)' "$in/$f.json" > "$out/$f.json"
done
for f in data-flow-diagram data-asset-diagram; do
  sort "$in/$f.gv" > "$out/$f.gv.sorted"
done
# Excel: Zellinhalte (sharedStrings) zeilenweise sortiert, Zeitstempel/Metadaten ignoriert
for x in risks tags; do
  tmp=$(mktemp -d); unzip -oq "$in/$x.xlsx" -d "$tmp"
  grep -o '<t[^>]*>[^<]*</t>' "$tmp/xl/sharedStrings.xml" | sort > "$out/$x.xlsx.strings.txt"
  rm -r "${tmp:?}"
done
