# feat(rules): zehn weitere Built-in-Regeln aus der Abdeckungsanalyse

## Motivation
`docs/rule-proposals.md` vergleicht die vorhandenen Regeln mit OWASP Top 10, ASVS, den nicht portierten pytm-Mustern und den Upstream-Issues. Die auffälligsten Lücken lagen bei A07 (Brute Force, Session-Management) und A09 (Monitoring); dazu kamen Autorisierung technischer Zugriffe (Upstream #9), Redundanz, internet-exponierte Datastores (#26/#27), hard-codierte Secrets und KI-Agenten.

## Regeln
| Regel-ID | Art | Kurzbedingung | CWE |
|---|---|---|---|
| `missing-brute-force-protection` | tag-frei | Credentials-Login von internet-exponierten oder menschlich bedienten Aufrufern | 307 |
| `missing-authorization` | tag-frei | authentifizierter Link ohne Autorisierung auf sensible Nicht-Endnutzer-Assets | 862 |
| `missing-monitoring` | tag-frei, modellweit | sensible Assets, aber kein `monitoring`/`ids`/`ips`-Asset | 778 |
| `sensitive-data-in-logs` | tag-frei | Monitoring-Asset verarbeitet Daten ≥ confidential | 532 |
| `missing-redundancy` | tag-frei | mission-critical Verfügbarkeit, nicht redundant, kein Client | 1008 |
| `internet-exposed-datastore` | tag-frei | Datastore mit `internet: true` und gespeicherten Daten ≥ confidential | 284 |
| `weak-session-management` | Tag `session-tokens` | Web-Asset mit Tag, von Menschen über Web-Protokoll genutzt | 613 |
| `os-command-injection` | Tag `executes-os-commands` | eigenentwickeltes Asset mit Tag, nicht vertrauenswürdige Aufrufer | 78 |
| `hardcoded-credentials` | Tag `credentials-hardcoded` (Datenasset) | getaggtes Datenasset wird gespeichert/verarbeitet | 798 |
| `llm-excessive-agency` | Tags `ai-agent`, `executes-code` | KI-Asset mit Tag; Links zu Assets ≥ critical Integrity bzw. Codeausführung | 250 |

Mitgezogene Korrektur an den zehn pytm-Regeln: Out-of-Scope-Aufrufer unterdrücken keine Risiken mehr; Link-Risiko-IDs folgen der Konvention `kategorie@aufrufer@ziel@link-id`.

## Tests
Je Regel Positiv- und Negativfälle (`pkg/risks/builtin/proposed_rules_test.go`), Metadaten-Vollständigkeit, leeres Modell, Out-of-Scope-Aufrufer. Beispielmodell: 68 → 77 Risiken, nur Zusätze (Details in `docs/rule-proposals.md`, Abschnitt 5). Lint 0 Issues.

## Hinweise
- Bestehende Regeln unverändert; README und Versionsnummer unverändert.
- Die vier tag-basierten Regeln registrieren ihre Tags über `SupportedTags()`; `threagile list-risk-rules` zeigt sie an.
