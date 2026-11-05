#!/usr/bin/env bash
# Legt die Referenzdateien für die Claude-Code-Cloud-Sessions an.
# Einmalig LOKAL im Fork ausführen (nicht in der Cloud), danach committen.
#
# Voraussetzungen: git, gh (eingeloggt: gh auth status), curl, jq
# Aufruf aus dem Repo-Root:  bash scripts/prepare-reference.sh

set -euo pipefail

REF_DIR="docs/reference"
PYTM_REPO="OWASP/pytm"
UPSTREAM_REPO="Threagile/threagile"

mkdir -p "$REF_DIR"

echo "==> Prüfe gh-Login"
gh auth status >/dev/null

echo "==> Ermittle aktuellen pytm-Commit"
PYTM_SHA=$(gh api "repos/${PYTM_REPO}/commits/master" --jq .sha)
echo "    ${PYTM_SHA}"

echo "==> Lade pytm-Dateien (gepinnt auf ${PYTM_SHA:0:12})"
curl -fsSL "https://raw.githubusercontent.com/${PYTM_REPO}/${PYTM_SHA}/pytm/threatlib/threats.json" \
  -o "${REF_DIR}/pytm-threats.json"
curl -fsSL "https://raw.githubusercontent.com/${PYTM_REPO}/${PYTM_SHA}/pytm/pytm.py" \
  -o "${REF_DIR}/pytm-pytm.py"
curl -fsSL "https://raw.githubusercontent.com/${PYTM_REPO}/${PYTM_SHA}/LICENSE" \
  -o "${REF_DIR}/pytm-LICENSE"

echo "==> Exportiere offene Upstream-Issues aus ${UPSTREAM_REPO}"
gh issue list \
  --repo "${UPSTREAM_REPO}" \
  --state open \
  --limit 500 \
  --json number,title,body,labels,createdAt,updatedAt,author,comments,url \
  > "${REF_DIR}/upstream-issues.json"

ISSUE_COUNT=$(jq length "${REF_DIR}/upstream-issues.json")

echo "==> Schreibe Herkunftsnachweis"
cat > "${REF_DIR}/README.md" << README
# Referenzdateien für die Cloud-Sessions

Automatisch erzeugt von \`scripts/prepare-reference.sh\` am $(date -u +%Y-%m-%dT%H:%M:%SZ).
Nur lesen – nicht von Hand bearbeiten. Zum Aktualisieren das Skript erneut ausführen.

| Datei | Quelle | Stand |
|---|---|---|
| pytm-threats.json | ${PYTM_REPO} – pytm/threatlib/threats.json | Commit ${PYTM_SHA} |
| pytm-pytm.py | ${PYTM_REPO} – pytm/pytm.py | Commit ${PYTM_SHA} |
| pytm-LICENSE | ${PYTM_REPO} – LICENSE | Commit ${PYTM_SHA} |
| upstream-issues.json | ${UPSTREAM_REPO} – offene Issues (${ISSUE_COUNT} Stück) | Export $(date -u +%Y-%m-%d) |

Die pytm-Dateien dienen ausschließlich als Lesevorlage für das Mapping in
Phase 1 (siehe CLAUDE.md). Es wird kein Code aus pytm übernommen.
README

echo
echo "Fertig. ${ISSUE_COUNT} Issues exportiert, pytm auf ${PYTM_SHA:0:12} gepinnt."
echo "Jetzt committen:"
echo "  git add ${REF_DIR} && git commit -m 'docs(reference): add pytm snapshot and upstream issue export'"
