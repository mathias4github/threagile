# Vorschläge für weitere Built-in-Regeln

Stand nach Phase 3 und Regel-Review (52 Built-in-Regeln). Methode: Abgleich der vorhandenen Regeln mit
(a) den nicht portierten pytm-Mustern (`docs/pytm-mapping.md`), (b) OWASP Top 10 2021 und ASVS-4.0-Kapiteln,
(c) den offenen Upstream-Issues (`docs/bug-triage.md`), (d) typischen Cloud- und KI-Architekturen.
Nur Vorschläge, nichts davon ist umgesetzt.

## 1. Abdeckung OWASP Top 10 (2021) durch die vorhandenen Regeln

| Kategorie | abgedeckt durch | Lücke |
|---|---|---|
| A01 Broken Access Control | missing-authentication, missing-identity-propagation, unguarded-access-from-internet, unguarded-direct-datastore-access, path-traversal, CSRF | Autorisierung technischer Zugriffe (siehe Vorschlag 2) |
| A02 Cryptographic Failures | unencrypted-communication, unencrypted-asset, missing-vault | – |
| A03 Injection | sql-nosql-, ldap-, search-query-, mail-command-injection, XSS, XXE, path-traversal | OS-Command-Injection (nur tag-basiert abbildbar) |
| A04 Insecure Design | missing-network-segmentation, mixed-targets-on-shared-runtime, missing-identity-provider-isolation, shared-datastore-tampering, … | fehlende Redundanz (Vorschlag 5) |
| A05 Security Misconfiguration | missing-hardening, missing-cloud-hardening, missing-waf, missing-clickjacking-protection | – |
| A06 Vulnerable Components | unchecked-deployment, container-baseimage-backdooring | nicht modellierbar (keine Versionsdaten) |
| A07 Identification & Authentication Failures | missing-authentication, missing-authentication-second-factor | Brute-Force-Schutz (Vorschlag 1), Session-Management (tag-basiert) |
| A08 Software & Data Integrity | code-backdooring, push-instead-of-pull-deployment, untrusted-deserialization, accidental-secret-leak | – |
| A09 Logging & Monitoring Failures | audit-log-manipulation | fehlendes Monitoring (Vorschlag 3), sensible Daten in Logs (Vorschlag 4) |
| A10 SSRF | server-side-request-forgery | – |

## 2. Vorschläge ohne Tags (mit dem bestehenden Datenmodell ausdrückbar)

| Prio | Regel-ID | Bedingung (Threagile-Begriffe) | Bewertung | CWE | Überschneidung / Hinweis |
|---|---|---|---|---|---|
| 1 | `missing-brute-force-protection` | Eingehender Link mit `authentication: credentials` auf ein In-Scope-Asset, Quelle ist internet-exponiert (`internet: true`) oder menschlicher Client; Impact nach CIA des Ziels | Likely wenn aus dem Internet, sonst Unlikely | 307 | Ergänzt `missing-authentication-second-factor` (2FA) um Lockout/Rate-Limiting; ein Risiko je Asset |
| 2 | `missing-authorization` | Eingehender Link mit `authentication != none` und `authorization: none` auf ein In-Scope-Asset, das Daten ≥ confidential oder ≥ critical verarbeitet und **nicht** Endnutzer-Anfragen verarbeitet (sonst greift `missing-identity-propagation`) – z. B. Datastores, Message Queues, interne Services | Impact nach CIA | 862 | Upstream-Issue #9; ein Risiko je Link |
| 3 | `missing-monitoring` | Modell enthält In-Scope-Assets mit Confidentiality ≥ confidential oder Integrity/Availability ≥ critical, aber kein Asset mit Technologie `monitoring` (bzw. `ids`/`ips`) | Medium, Modell-weit, ein Risiko (Muster wie `missing-vault`, `missing-waf`) | 778 | Muster „fehlender Baustein“ wie `missing-vault` |
| 4 | `sensitive-data-in-logs` | Asset mit Technologie `monitoring`, das Datenassets ≥ confidential verarbeitet (`data_assets_processed`) oder per Link empfängt | Impact nach Confidentiality | 532 | Ergänzt `audit-log-manipulation` (Integrität) um Vertraulichkeit |
| 5 | `missing-redundancy` | In-Scope-Asset mit `availability: mission-critical` (Asset oder verarbeitete Daten) und `redundant: false`, kein Client-Typ | Medium; Likelihood Unlikely | 1008 | `dos-risky-access-across-trust-boundary` nutzt `redundant` nur zur Abschwächung; eine eigene Regel macht den Single Point of Failure sichtbar |
| 6 | `internet-exposed-datastore` | Asset vom Typ `datastore` mit `internet: true` und gespeicherten Daten ≥ confidential | High Impact bei strictly-confidential | 284 | `unguarded-access-from-internet` braucht einen modellierten Internet-Client; dieser Vorschlag greift schon am Asset-Flag (Upstream-Issues #26/#27: öffentliche Buckets/Snapshots) |

Empfehlung: 1–4 umsetzen (klar abgrenzbar, geringe Fehlalarmrate), 5 und 6 nach Rücksprache (Abhängigkeit von der Modellierungsdisziplin bei `redundant` und `internet`).

## 3. Vorschläge mit Tag (Modellierer muss ein Tag setzen)

Aus `docs/pytm-mapping.md` (TAG-BASIERT), hier die vier mit dem besten Nutzen:

| Regel-ID | Tag (auf Asset bzw. Datenasset) | Bedingung | CWE |
|---|---|---|---|
| `weak-session-management` | `session-tokens` auf Web-Asset | Web-Asset mit Tag, erreicht von menschlichen Clients | 613 |
| `os-command-injection` | `executes-os-commands` | Asset mit Tag und `custom_developed_parts`, eingehende Links aus anderem Netz oder von Menschen | 78 |
| `hardcoded-credentials` | `credentials-hardcoded` auf Datenasset | Datenasset mit Tag wird von einem In-Scope-Asset verarbeitet oder übertragen | 798 |
| `llm-excessive-agency` | `ai-agent`, `executes-code` auf `ai`-Asset | KI-Asset mit Tag und ausgehenden Links zu Assets mit Integrity ≥ critical | 1427 / 250 |

Die Tags müssten in `SupportedTags()` der jeweiligen Regel registriert werden, damit sie in der Modellvalidierung bekannt sind.

## 4. Bewusst nicht vorgeschlagen

- `json-hijacking` (pytm SC01): veraltetes Angriffsmuster, moderne Browser verhindern es.
- Generische „fehlende Eingabevalidierung“ (pytm INP10/14/25 u. a.): nicht modellierbar, würde für jedes Asset feuern.
- Veraltete Komponenten (A06): keine Versions- oder Patch-Daten im Modell; `unchecked-deployment` adressiert den Prozess.
- Sprach-/Produkt-spezifische Muster (PHP Remote File Inclusion, Format-String, Buffer Overflow): nur per Tag und mit geringem Zusatznutzen gegenüber `missing-hardening`.
