#!/usr/bin/env bash
# Runs the example model like the Docker image does and compares the normalized
# output with test/golden/baseline/normalized.
#
#   scripts/golden-run.sh            # compare, exit 1 on difference
#   scripts/golden-run.sh --update   # regenerate test/golden/baseline
#
# Needs: go, jq, unzip, graphviz (dot).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -r "${work:?}"' EXIT

app="$work/app"; out="$work/out"; mkdir -p "$app" "$out"
cp "$repo/report/template/background.pdf" "$repo/support/openapi.yaml" "$repo/support/schema.json" \
   "$repo/support/live-templates.txt" "$repo/LICENSE.txt" "$app/"
cp -r "$repo/server" "$app/server"
cp "$repo/demo/example/threagile.yaml" "$app/threagile-example-model.yaml"
cp "$repo/demo/example/threagile.yaml" "$out/threagile-example-model.yaml"

(cd "$repo" && go build -o "$app/threagile" ./cmd/threagile)
(cd "$app" && ./threagile analyze-model --app-dir "$app" --model "$out/threagile-example-model.yaml" \
   --output "$out" --keep-diagram-source-files > "$work/log.txt" 2>&1) || { cat "$work/log.txt"; exit 1; }

golden="$repo/test/golden/baseline"
if [ "${1:-}" = "--update" ]; then
  cp "$out"/{risks.json,stats.json,technical-assets.json,risks.xlsx,tags.xlsx,data-flow-diagram.gv,data-asset-diagram.gv} "$golden/"
  cp "$repo/demo/example/threagile.yaml" "$golden/threagile-example-model.yaml"
  "$repo/scripts/golden-normalize.sh" "$out" "$golden/normalized"
  echo "golden baseline updated"
  exit 0
fi

"$repo/scripts/golden-normalize.sh" "$out" "$work/normalized"
if diff -r "$golden/normalized" "$work/normalized"; then
  echo "GOLDEN OK"
else
  echo "GOLDEN DIFF"
  exit 1
fi
