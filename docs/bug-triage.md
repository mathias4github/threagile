# Bug-Triage (Phase 0c)

Quelle: `docs/reference/upstream-issues.json` (43 offene Upstream-Issues). Stand Code: `master` + Phase 0b (PR 2, noch nicht gemergt).
Geprüft wurde am Code bzw. mit Minimal-Modell; Anhänge (z. B. das Zip aus #164) liegen nicht vor.

## REPRODUZIERBAR
| # | Titel | Befund |
|---|---|---|
| 130 | `individual_risk_categories` ohne Rückwärtskompatibilität | Parser (`pkg/input/model.go:222`) kennt nur `custom_risk_categories`. `demo/example/threagile.yaml:1243`, `demo/stub/threagile.yaml:203`, `support/schema.json:990` und `pkg/server/model.go:78` nutzen weiter `individual_risk_categories` → dort definierte Custom-Risiken werden **stillschweigend ignoriert**. |
| 96 | `risks.json` unvollständig gegenüber `risks.xlsx` | Golden-Baseline bestätigt: JSON-Risiken enthalten kein `cwe`, der Excel-Export schon. (Grenzfall zu FEATURE; Fix ist klein: Feld ergänzen.) |

### Priorisierte Liste
1. **#130** – stille Datenverluste im Standard-Beispiel; Fix: beide Schlüssel akzeptieren (alt → Warnung) und Beispiel/Schema/Stub auf `custom_risk_categories` angleichen. Achtung Golden-Diff: Beispielmodell enthält evtl. ein Custom-Risiko, das dann erstmals erscheint (zulässig, erklärungspflichtig).
2. **#96** – `cwe` in `risks.json` ergänzen (Golden-Diff: nur Zusatzfeld).

## UNKLAR / nicht (mehr) reproduzierbar
| # | Titel | Grund |
|---|---|---|
| 164 | Divide by zero mit `includes` | Zip-Anhang nicht verfügbar. Versuch mit Stub-Modell, aufgeteilt per `includes` (data_assets/technical_assets/trust_boundaries ausgelagert): **kein Fehler**. Ursache vermutlich modellspezifisch (z. B. leere Liste in Report-Berechnung). Bitte Zip aus dem Issue bereitstellen. |
| 92 | Schema `end-user-identity-propagation` | Code (`pkg/types/authorization.go:34`), `schema.json:756` und Beispiel sind auf `master` konsistent; Issue beruht auf Docker-Hub-Image älter als `master`. Nichts zu fixen. |
| 12 | Unicode-Fehler im PDF | Von 2021, Referenz auf alte `report.go`-Zeile; kein Beispiel, kein `uni()` mehr im Code. |
| 34 | Fehler mit `Dockerfile.local` | `render-data-flow-diagram.sh` existiert nicht mehr (Graphviz wird direkt aufgerufen); veraltet. |
| 41 | Schema-URL threagile.io liefert Forbidden | Externer Webserver, nicht im Repo. |
| 121, 69, 93, 20 | Docker-Aufrufe/Volumes/Berechtigungen | Umgebungs- bzw. Aufrufproblem (Host-Mount, UID 1000, fehlendes `-v`-Quoting); siehe DOKU. |

## DOKU / USABILITY
#149 (Anbindung Asset-Datenbanken), #151 (physischer Transport modellieren), #121, #69, #93, #20 (Docker-Nutzung/Rechte), #85 (Mobile-Apps modellieren), #82 (Asset-IDs werden bewusst sanitisiert: „id is id“), #75 (Custom Risks Go vs. YAML), #13 (Doku zu Technologien/Protokollen), #99 (Security-Check-Container pinnen – CI-Konfiguration), #94 (bidirektionaler Pfeil: Maintainer-Konvention „Pfeil = target“, Diskussion offen).

## FEATURE
#160 (OT/ICS-Technologien), #97 (DOT-Export; per `--keep-diagram-source-files` bereits möglich → eher Doku), #84 (PDF-Inhaltsverzeichnis), #80 (GitHub Actions/Docker-Tags), #60 (PKL), #52 (Regeln entkoppeln), #51 (Frontend), #49 (HTML-Report), #45 (Protokolle/Technologien in YAML), #35 (risks.json pretty-print), #33 (OTM-Export), #32 (Includes/CDK – Includes existieren inzwischen), #29/#28/#27/#26 (neue Cloud-Risikoregeln), #25 (Okta), #22 / #1 (Releases/Binaries), #17 (Lokalisierung), #16 (mehrere Autoren), #15 (Proxy-Verbindungen), #9 (Autorisierungsregel).

## Sonstiges / kein Fehlverhalten
#166 (Austausch mit dda-tara).

## Vorschlag
Nur #130 und #96 bearbeiten (je eigener Branch/Session: `fix/130-custom-risk-categories`, `fix/96-risks-json-cwe`). #164 erst nach Bereitstellung des Zips.
