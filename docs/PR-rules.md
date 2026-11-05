# feat(rules): zehn neue Built-in-Regeln, portiert aus OWASP pytm

## Motivation
OWASP pytm enthält einen Katalog von 114 Bedrohungsmustern. Ein Abgleich (`docs/pytm-mapping.md`) zeigt: 40 sind durch bestehende Threagile-Regeln abgedeckt, 20 lassen sich mit dem Threagile-Datenmodell (Technologie, Protokoll, Trust-Boundary, Datenformat, CIA) ausdrücken, 27 nur per Tag, 27 nicht. Dieser PR ergänzt die portierbaren Muster, zusammengefasst zu zehn Regeln.

## Regeln
| Regel-ID | pytm-SIDs | Kurzbegründung |
|---|---|---|
| `http-request-smuggling` | INP04, INP36, INP37 | Proxy/Load-Balancer/Gateway/WAF vor Web-/App-Server: uneinheitliches HTTP-Parsing |
| `mail-command-injection` | INP15 | In-Scope-Clients greifen per SMTP/IMAP auf Mail-Server zu |
| `missing-clickjacking-protection` | INP20 | Web-Anwendung wird von menschlichem Client über Web-Protokoll genutzt |
| `shared-datastore-tampering` | AC02 | Datastore mit schreibenden Zugriffen aus ≥ 2 Trust-Boundaries |
| `xml-entity-expansion-dos` | DO03, DO04, DO05, INP22, INP34 | XML/SOAP-Asset aus dem Internet oder über Boundary erreichbar |
| `llm-prompt-injection` | LLM01, LLM07 | KI-Asset mit Eingaben von Menschen, Internet oder anderer Boundary |
| `ai-sensitive-data-exposure` | LLM03, LLM08 | KI-Asset mit vertraulichen Daten in Cloud-Boundary oder mit Ausgang zu weniger geschützten Assets |
| `client-reverse-engineering` | HA02, HA04 | Mobile-App/Desktop/IoT mit eigenem Code und sensiblen Daten |
| `audit-log-manipulation` | DE04 | Monitoring-Asset mit schreibendem Zugriff aus anderer Boundary |
| `xml-schema-poisoning` | AC04 | XML-akzeptierendes Asset mit Link ohne Autorisierung |

Nicht portiert: `json-hijacking` (SC01, veraltet), tag-basierte Vorschläge (siehe Mapping). Einige pytm-Bedingungen sind fehlerhaft (z. B. invertierte XML-Parser-Logik in INP19/21/22); sie wurden nicht übernommen, sondern mit korrekter Bedingung neu formuliert (`docs/pytm-mapping.md`, Abschnitt 4).

## Tests
Jede Regel hat Unit-Tests mit Positiv- und Negativfällen (`pkg/risks/builtin/*_rule_test.go`) sowie einen gemeinsamen Test auf leerem Modell. Beispielmodell: 63 → 68 Risiken (nur Zusätze: 2× `http-request-smuggling`, 1× `xml-entity-expansion-dos`); bestehende Risiken, Assets und Diagramme unverändert.

## Herkunft
Die Bedrohungsmuster stammen aus OWASP pytm (`threatlib/threats.json`, permissive Lizenz, siehe `docs/reference/pytm-LICENSE`). Es wurde kein Code und kein Text wörtlich übernommen; Beschreibungen, Mitigationen und Referenzen sind eigenständig im Stil der bestehenden Threagile-Regeln formuliert.

## Hinweise
- Bestehende Regeln sind unverändert; README und Versionsnummer ebenfalls.
- Der Branch enthält auch Phase-1-Dokumentation (`docs/pytm-mapping.md`).
