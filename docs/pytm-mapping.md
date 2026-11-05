# pytm → Threagile: Regel-Mapping (Phase 1)

Quelle: `docs/reference/pytm-threats.json` (114 Bedrohungen, OWASP pytm, Commit 5c0ecddb; Lizenz `docs/reference/pytm-LICENSE`). Es wird kein pytm-Text übernommen; Titel sind nur Bezeichner.

**Grenze der Analyse:** `docs/reference/pytm-pytm.py` enthält nur die Modell-Laufzeit; die Definitionen von `Controls`, `Element`, `Server`, `Process` usw. (Module `base`, `element`, `asset`, …) liegen nicht im Snapshot. Welche Attribute für welchen Zieltyp existieren, ist daher nur teilweise belegt; Hinweise darauf stehen unter „Fehlerhafte Bedingungen“ mit Vorbehalt.

## 1. Built-in-Regeln in Threagile vor der Portierung (42; danach 52)

`accidental-secret-leak`, `code-backdooring`, `container-baseimage-backdooring`, `container-platform-escape`, `cross-site-request-forgery`, `cross-site-scripting`, `dos-risky-access-across-trust-boundary`, `incomplete-model`, `ldap-injection`, `missing-authentication`, `missing-authentication-second-factor`, `missing-build-infrastructure`, `missing-cloud-hardening`, `missing-file-validation`, `missing-hardening`, `missing-identity-propagation`, `missing-identity-provider-isolation`, `missing-identity-store`, `missing-network-segmentation`, `missing-vault`, `missing-vault-isolation`, `missing-waf`, `mixed-targets-on-shared-runtime`, `path-traversal`, `push-instead-of-pull-deployment`, `search-query-injection`, `server-side-request-forgery`, `service-registry-poisoning`, `sql-nosql-injection`, `unchecked-deployment`, `unencrypted-asset`, `unencrypted-communication`, `unguarded-access-from-internet`, `unguarded-direct-datastore-access`, `unnecessary-communication-link`, `unnecessary-data-asset`, `unnecessary-data-transfer`, `unnecessary-technical-asset`, `untrusted-deserialization`, `wrong-communication-link-content`, `wrong-trust-boundary-content`, `xml-external-entity`

Modellbausteine, auf die Bedingungen aufsetzen können: Technologie (z. B. `mail-server`, `reverse-proxy`, `load-balancer`, `gateway`, `waf`, `web-server`, `application-server`, `web-application`, `web-service-soap/-rest`, `mobile-app`, `desktop`, `iot-device`, `ai`, `monitoring`, …, Attribute siehe `pkg/types/technologies.yaml`), Link-Protokoll (u. a. `smtp`, `imap`, `pop3`, `http`, `https`, `ldap`, …), Link-Eigenschaften (`vpn`, `ip_filtered`, `readonly`, `authentication`, `authorization`), Datenformat (`json`, `xml`, …), Asset-Eigenschaften (`internet`, `multi_tenant`, `redundant`, `custom_developed_parts`, `out_of_scope`, `used_as_client_by_human`, `encryption`, CIA), Trust-Boundary-Typen (z. B. `network-cloud-provider`), Tags auf Assets/Links/Datenassets.

## 2. Zusammenfassung

| Status | Anzahl SIDs |
|---|---|
| ABGEDECKT | 40 |
| PORTIERBAR | 20 |
| TAG-BASIERT | 27 |
| NICHT ABBILDBAR | 27 |

Viele pytm-Bedingungen hängen an `controls.*`-Flags (validatesInput, sanitizesInput, …), die Threagile bewusst nicht modelliert: Threagile nimmt die Gegenmaßnahme als zu prüfen an und lässt den Status über Risk-Tracking führen. Solche Bedrohungen sind entweder durch eine spezifische Threagile-Kategorie abgedeckt, über ein Tag abbildbar oder nicht abbildbar.

## 3. Mapping aller SIDs

| SID | Titel | Status | Threagile-Pendant | Begründung | geplante Bedingung |
|---|---|---|---|---|---|
| INP01 | Buffer Overflow via Environment Variables | TAG-BASIERT | - | Speichersicherheit der Implementierung ist nicht modelliert | Tag memory-unsafe-code auf Asset mit custom_developed_parts und eingehenden Links von anderer Trust-Boundary. Regel-ID-Vorschlag: buffer-overflow-risk |
| INP02 | Overflow Buffers | TAG-BASIERT | - | Speichersicherheit der Implementierung ist nicht modelliert | Tag memory-unsafe-code auf Asset mit custom_developed_parts und eingehenden Links von anderer Trust-Boundary. Regel-ID-Vorschlag: buffer-overflow-risk |
| INP03 | Server Side Include (SSI) Injection | TAG-BASIERT | - | SSI-Nutzung nicht modelliert | Tag ssi-enabled auf Asset mit Technologie web-server. Regel-ID-Vorschlag: ssi-injection |
| CR01 | Session Sidejacking | ABGEDECKT | unencrypted-communication (+ unencrypted-asset bei DR01) | unverschlüsselte/ungeschützte Kommunikation; TLS-Version/Zertifikatsprüfung nicht modelliert | – |
| INP04 | HTTP Request Splitting | PORTIERBAR | `http-request-smuggling` (neu, umgesetzt) | Front-End/Back-End-Kette ist über Technologie und Links erkennbar | Link von Asset mit Technologie reverse-proxy/load-balancer/gateway/waf zu Asset mit Technologie web-server/application-server/web-application über http oder https. Eine Regel für alle drei SIDs. Regel-ID-Vorschlag: http-request-smuggling |
| CR02 | Cross Site Tracing | NICHT ABBILDBAR | - | TRACE-Methode/Session-Tokens nicht modelliert | – |
| INP05 | Command Line Execution through SQL Injection | ABGEDECKT | sql-nosql-injection | SQL-Injection über Server/SOAP; Threagile prüft Link zu Datenbank-Asset | – |
| INP06 | SQL Injection through SOAP Parameter Tampering | ABGEDECKT | sql-nosql-injection | SQL-Injection über Server/SOAP; Threagile prüft Link zu Datenbank-Asset | – |
| SC01 | JSON Hijacking (aka JavaScript Hijacking) | PORTIERBAR | - | JSON-Datenformat und Web-Technologie modelliert | Asset mit Attribut web_application oder Technologie web-service-rest, das json akzeptiert, und menschlicher Client mit Datenassets ab confidential. Veraltetes Angriffsmuster (moderne Browser) – Empfehlung: nicht portieren |
| LB01 | API Manipulation | NICHT ABBILDBAR | - | API-Implementierung/Validierung nicht modelliert | – |
| AA01 | Authentication Abuse/ByPass | ABGEDECKT | missing-authentication | fehlende Authentifizierung/Principal-Spoofing; teils auch missing-authentication-second-factor | – |
| DS01 | Excavation | NICHT ABBILDBAR | - | Validierung/Kodierung nicht modelliert | – |
| DE01 | Interception | ABGEDECKT | unencrypted-communication (+ unencrypted-asset bei DR01) | unverschlüsselte/ungeschützte Kommunikation; TLS-Version/Zertifikatsprüfung nicht modelliert | – |
| DE02 | Double Encoding | NICHT ABBILDBAR | - | Kodierungs-/Validierungskontrollen nicht modelliert | – |
| API01 | Exploit Test APIs | TAG-BASIERT | - | Test-Endpunkte in Produktion nicht modelliert | Tag exposes-test-api auf Asset mit Technologie web-service-rest/web-service-soap/gateway. Regel-ID-Vorschlag: exposed-test-api |
| AC01 | Privilege Abuse | ABGEDECKT | missing-identity-propagation | Rechte-/Funktionsmissbrauch durch fehlende Autorisierung des Endnutzers (teilweise) | – |
| INP07 | Buffer Manipulation | TAG-BASIERT | - | Speichersicherheit der Implementierung ist nicht modelliert | Tag memory-unsafe-code auf Asset mit custom_developed_parts und eingehenden Links von anderer Trust-Boundary. Regel-ID-Vorschlag: buffer-overflow-risk |
| AC02 | Shared Data Manipulation | PORTIERBAR | `shared-datastore-tampering` (neu, umgesetzt) | Mehrfachzugriff auf Datenhaltung ist über Links erkennbar | Technisches Asset vom Typ datastore mit schreibenden (nicht readonly) eingehenden Links von mindestens zwei Quell-Assets in verschiedenen Trust-Boundaries; Impact aus Integrity. Regel-ID-Vorschlag: shared-datastore-tampering |
| DO01 | Flooding | ABGEDECKT | dos-risky-access-across-trust-boundary | Flooding/Ressourcenverbrauch nur für Zugriffe über Trust-Boundaries abgedeckt (teilweise) | – |
| HA01 | Path Traversal | ABGEDECKT | path-traversal | Path-Traversal (absolut/relativ) | – |
| AC03 | Subverting Environment Variable Values | NICHT ABBILDBAR | - | Umgebungsvariablen/Autorisierungsschema sind keine Modell-Attribute | – |
| DO02 | Excessive Allocation | ABGEDECKT | dos-risky-access-across-trust-boundary | Flooding/Ressourcenverbrauch nur für Zugriffe über Trust-Boundaries abgedeckt (teilweise) | – |
| DS02 | Try All Common Switches | NICHT ABBILDBAR | - | keine Schwachstellenbedingung – feuert für jede Produktivumgebung | – |
| INP08 | Format String Injection | NICHT ABBILDBAR | - | Format-String-Verhalten der Implementierung nicht modelliert | – |
| INP09 | LDAP Injection | ABGEDECKT | ldap-injection | LDAP-Injection | – |
| INP10 | Parameter Injection | NICHT ABBILDBAR | - | Parameter-Validierung nicht modelliert | – |
| INP11 | Relative Path Traversal | ABGEDECKT | path-traversal | Path-Traversal (absolut/relativ) | – |
| INP12 | Client-side Injection-induced Buffer Overflow | TAG-BASIERT | - | Speichersicherheit der Implementierung ist nicht modelliert | Tag memory-unsafe-code auf Asset mit custom_developed_parts und eingehenden Links von anderer Trust-Boundary. Regel-ID-Vorschlag: buffer-overflow-risk |
| AC04 | XML Schema Poisoning | PORTIERBAR | `xml-schema-poisoning` (neu, umgesetzt) | Link-Autorisierung und Datenformat sind modelliert | Eingehender Link mit authorization none, der ein Datenasset im Format xml an ein Asset überträgt, das xml akzeptiert. Geringe Priorität. Regel-ID-Vorschlag: xml-schema-poisoning |
| DO03 | XML Ping of the Death | PORTIERBAR | `xml-entity-expansion-dos` (neu, umgesetzt) | Datenformat xml/SOAP ist modelliert (data_formats_accepted, Technologie web-service-soap) | Nicht ausgeschlossenes Asset, das xml akzeptiert (oder Technologie web-service-soap) und von außerhalb seiner Trust-Boundary bzw. aus dem Internet erreichbar ist; Impact aus Availability. Eine Regel (CWE-776/CWE-770). Regel-ID-Vorschlag: xml-entity-expansion-dos |
| AC05 | Content Spoofing | ABGEDECKT | unencrypted-communication (+ unencrypted-asset bei DR01) | unverschlüsselte/ungeschützte Kommunikation; TLS-Version/Zertifikatsprüfung nicht modelliert | – |
| INP13 | Command Delimiters | TAG-BASIERT | - | Ausführen von OS-Befehlen ist nicht modelliert | Tag executes-os-commands auf Asset mit custom_developed_parts und eingehenden Links. Regel-ID-Vorschlag: os-command-injection |
| INP14 | Input Data Manipulation | NICHT ABBILDBAR | - | generische Eingabevalidierung nicht modelliert | – |
| DE03 | Sniffing Attacks | ABGEDECKT | unencrypted-communication (+ unencrypted-asset bei DR01) | unverschlüsselte/ungeschützte Kommunikation; TLS-Version/Zertifikatsprüfung nicht modelliert | – |
| CR03 | Dictionary-based Password Attack | ABGEDECKT | missing-authentication-second-factor | Wörterbuchangriff auf Passwörter; 2FA als Gegenmaßnahme (teilweise) | – |
| API02 | Exploit Script-Based APIs | NICHT ABBILDBAR | - | API-Implementierung/Validierung nicht modelliert | – |
| HA02 | White Box Reverse Engineering | PORTIERBAR | `client-reverse-engineering` (neu, umgesetzt) | Client-Assets mit Technologie sind modelliert | Asset mit Technologie mobile-app, desktop oder iot-device (ggf. client-system), nicht ausgeschlossen, mit eigenentwickelten Teilen oder gespeicherten Daten ab Vertraulichkeit confidential/Integrität critical. Eine Regel. Regel-ID-Vorschlag: client-reverse-engineering |
| DS03 | Footprinting | ABGEDECKT | missing-hardening | Footprinting/Fingerprinting; Härtung als Gegenmaßnahme (teilweise) | – |
| AC06 | Using Malicious Files | ABGEDECKT | missing-file-validation | Missbrauch von Dateien/Dateiinhalt (teilweise) | – |
| HA03 | Web Application Fingerprinting | ABGEDECKT | missing-hardening | Footprinting/Fingerprinting; Härtung als Gegenmaßnahme (teilweise) | – |
| SC02 | XSS Targeting Non-Script Elements | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| AC07 | Exploiting Incorrectly Configured Access Control Security Levels | NICHT ABBILDBAR | - | Zugriffskontroll-Stufen (hasAccessControl) sind nicht modelliert | – |
| INP15 | IMAP/SMTP Command Injection | PORTIERBAR | `mail-command-injection` (neu, umgesetzt) | Mail-Protokolle und Mail-Technologie sind modellierbar | Asset mit Technologie mail-server (oder Link mit Protokoll smtp/smtp-encrypted/imap/imap-encrypted/pop3/pop3-encrypted); eingehender Link von Asset mit eigenentwickelten Teilen oder Endnutzer-Zugriff; Impact aus CIA der verarbeiteten Daten. Regel-ID-Vorschlag: mail-command-injection |
| HA04 | Reverse Engineering | PORTIERBAR | `client-reverse-engineering` (neu, umgesetzt) | Client-Assets mit Technologie sind modelliert | Asset mit Technologie mobile-app, desktop oder iot-device (ggf. client-system), nicht ausgeschlossen, mit eigenentwickelten Teilen oder gespeicherten Daten ab Vertraulichkeit confidential/Integrität critical. Eine Regel. Regel-ID-Vorschlag: client-reverse-engineering |
| SC03 | Embedding Scripts within Scripts | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| INP16 | PHP Remote File Inclusion | NICHT ABBILDBAR | - | Sprache/Include-Mechanismus (PHP) nicht modelliert | – |
| AA02 | Principal Spoof | ABGEDECKT | missing-authentication | fehlende Authentifizierung/Principal-Spoofing; teils auch missing-authentication-second-factor | – |
| CR04 | Session Credential Falsification through Forging | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| DO04 | XML Entity Expansion | PORTIERBAR | `xml-entity-expansion-dos` (neu, umgesetzt) | Datenformat xml/SOAP ist modelliert (data_formats_accepted, Technologie web-service-soap) | Nicht ausgeschlossenes Asset, das xml akzeptiert (oder Technologie web-service-soap) und von außerhalb seiner Trust-Boundary bzw. aus dem Internet erreichbar ist; Impact aus Availability. Eine Regel (CWE-776/CWE-770). Regel-ID-Vorschlag: xml-entity-expansion-dos |
| DS04 | XSS Targeting Error Pages | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| SC04 | XSS Using Alternate Syntax | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| CR05 | Encryption Brute Forcing | NICHT ABBILDBAR | - | Verschlüsselungsalgorithmus nicht modelliert | – |
| AC08 | Manipulate Registry Information | ABGEDECKT | service-registry-poisoning | Manipulation von Registry-Informationen | – |
| DS05 | Lifting Sensitive Data Embedded in Cache | TAG-BASIERT | - | Caching ist nicht modelliert | Tag uses-cache auf Asset, das Daten ab confidential verarbeitet. Regel-ID-Vorschlag: sensitive-data-in-cache |
| SC05 | Removing Important Client Functionality | TAG-BASIERT | - | Code-Signing/Integrität des Client-Codes nicht modelliert | Tag unsigned-client-code auf Asset mit Technologie mobile-app/desktop/browser-nahem Client. Regel-ID-Vorschlag: client-code-tampering |
| INP17 | XSS Using MIME Type Mismatch | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| AA03 | Exploitation of Trusted Credentials | NICHT ABBILDBAR | - | Credential-Stärke/Session-Identifier nicht modelliert | – |
| AC09 | Functionality Misuse | ABGEDECKT | missing-identity-propagation | Rechte-/Funktionsmissbrauch durch fehlende Autorisierung des Endnutzers (teilweise) | – |
| INP18 | Fuzzing and observing application log data/errors for application mapping | NICHT ABBILDBAR | - | Logging/Fehlerausgabe nicht modelliert | – |
| CR06 | Communication Channel Manipulation | ABGEDECKT | unencrypted-communication, missing-authentication | Kanalmanipulation: Teilaspekte (Verschlüsselung, Authentifizierung) abgedeckt | – |
| AC10 | Exploiting Incorrectly Configured SSL | NICHT ABBILDBAR | - | TLS-Version/Konfiguration ist nicht modelliert (nur Protokoll-Ebene encrypted/unencrypted) | – |
| CR07 | XML Routing Detour Attacks | ABGEDECKT | unencrypted-communication | XML über HTTP; Routing-Umleitung nur über Transportschutz adressierbar (teilweise) | – |
| AA04 | Exploiting Trust in Client | NICHT ABBILDBAR | - | Server-seitige Validierung ist kein Modell-Attribut | – |
| CR08 | Client-Server Protocol Manipulation | ABGEDECKT | unencrypted-communication (+ unencrypted-asset bei DR01) | unverschlüsselte/ungeschützte Kommunikation; TLS-Version/Zertifikatsprüfung nicht modelliert | – |
| INP19 | XML External Entities Blowup | ABGEDECKT | xml-external-entity | XML-Parser-/DTD-Missbrauch (XXE) | – |
| INP20 | iFrame Overlay | PORTIERBAR | `missing-clickjacking-protection` (neu, umgesetzt) | Web-Anwendung und menschlicher Client sind modelliert | Asset mit Attribut web_application, das über einen Link von einem Asset mit used_as_client_by_human erreicht wird (http/https). Regel-ID-Vorschlag: missing-clickjacking-protection (CWE-1021) |
| AC11 | Session Credential Falsification through Manipulation | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| INP21 | DTD Injection | ABGEDECKT | xml-external-entity | XML-Parser-/DTD-Missbrauch (XXE) | – |
| INP22 | XML Attribute Blowup | PORTIERBAR | `xml-entity-expansion-dos` (neu, umgesetzt) | Datenformat xml/SOAP ist modelliert (data_formats_accepted, Technologie web-service-soap) | Nicht ausgeschlossenes Asset, das xml akzeptiert (oder Technologie web-service-soap) und von außerhalb seiner Trust-Boundary bzw. aus dem Internet erreichbar ist; Impact aus Availability. Eine Regel (CWE-776/CWE-770). Regel-ID-Vorschlag: xml-entity-expansion-dos |
| INP23 | File Content Injection | ABGEDECKT | missing-file-validation | Missbrauch von Dateien/Dateiinhalt (teilweise) | – |
| DO05 | XML Nested Payloads | PORTIERBAR | `xml-entity-expansion-dos` (neu, umgesetzt) | Datenformat xml/SOAP ist modelliert (data_formats_accepted, Technologie web-service-soap) | Nicht ausgeschlossenes Asset, das xml akzeptiert (oder Technologie web-service-soap) und von außerhalb seiner Trust-Boundary bzw. aus dem Internet erreichbar ist; Impact aus Availability. Eine Regel (CWE-776/CWE-770). Regel-ID-Vorschlag: xml-entity-expansion-dos |
| AC12 | Privilege Escalation | NICHT ABBILDBAR | - | Prinzip der minimalen Rechte (implementsPOLP) nicht modelliert; Container-Ausbruch separat durch container-platform-escape | – |
| AC13 | Hijacking a privileged process | NICHT ABBILDBAR | - | implementsPOLP nicht modelliert | – |
| AC14 | Catching exception throw/signal from privileged block | NICHT ABBILDBAR | - | implementsPOLP/Signale nicht modelliert | – |
| INP24 | Filter Failure through Buffer Overflow | TAG-BASIERT | - | Speichersicherheit der Implementierung ist nicht modelliert | Tag memory-unsafe-code auf Asset mit custom_developed_parts und eingehenden Links von anderer Trust-Boundary. Regel-ID-Vorschlag: buffer-overflow-risk |
| INP25 | Resource Injection | NICHT ABBILDBAR | - | generische Eingabevalidierung nicht modelliert | – |
| INP26 | Code Injection | NICHT ABBILDBAR | - | generische Codeinjektion; Sprache/Interpreter nicht modelliert | – |
| INP27 | XSS Targeting HTML Attributes | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| INP28 | XSS Targeting URI Placeholders | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| INP29 | XSS Using Doubled Characters | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| INP30 | XSS Using Invalid Characters | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| INP31 | Command Injection | TAG-BASIERT | - | Ausführen von OS-Befehlen ist nicht modelliert | Tag executes-os-commands auf Asset mit custom_developed_parts und eingehenden Links. Regel-ID-Vorschlag: os-command-injection |
| INP32 | XML Injection | NICHT ABBILDBAR | - | generische Eingabevalidierung/Kodierung nicht modelliert | – |
| INP33 | Remote Code Inclusion | NICHT ABBILDBAR | - | Sprache/Include-Mechanismus nicht modelliert | – |
| INP34 | SOAP Array Overflow | PORTIERBAR | `xml-entity-expansion-dos` (neu, umgesetzt) | Datenformat xml/SOAP ist modelliert (data_formats_accepted, Technologie web-service-soap) | Nicht ausgeschlossenes Asset, das xml akzeptiert (oder Technologie web-service-soap) und von außerhalb seiner Trust-Boundary bzw. aus dem Internet erreichbar ist; Impact aus Availability. Eine Regel (CWE-776/CWE-770). Regel-ID-Vorschlag: xml-entity-expansion-dos |
| INP35 | Leverage Alternate Encoding | NICHT ABBILDBAR | - | Kodierungs-/Validierungskontrollen nicht modelliert | – |
| DE04 | Audit Log Manipulation | PORTIERBAR | `audit-log-manipulation` (neu, umgesetzt) | Protokoll-/Monitoring-Assets sind über Technologie erkennbar | Asset mit Technologie monitoring (oder Tag audit-log) mit schreibenden eingehenden Links aus anderer Trust-Boundary. Regel-ID-Vorschlag: audit-log-manipulation |
| AC15 | Schema Poisoning | NICHT ABBILDBAR | - | Schema-Rechtevergabe nicht modelliert | – |
| INP36 | HTTP Response Smuggling | PORTIERBAR | `http-request-smuggling` (neu, umgesetzt) | Front-End/Back-End-Kette ist über Technologie und Links erkennbar | Link von Asset mit Technologie reverse-proxy/load-balancer/gateway/waf zu Asset mit Technologie web-server/application-server/web-application über http oder https. Eine Regel für alle drei SIDs. Regel-ID-Vorschlag: http-request-smuggling |
| INP37 | HTTP Request Smuggling | PORTIERBAR | `http-request-smuggling` (neu, umgesetzt) | Front-End/Back-End-Kette ist über Technologie und Links erkennbar | Link von Asset mit Technologie reverse-proxy/load-balancer/gateway/waf zu Asset mit Technologie web-server/application-server/web-application über http oder https. Eine Regel für alle drei SIDs. Regel-ID-Vorschlag: http-request-smuggling |
| INP38 | DOM-Based XSS | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| AC16 | Session Credential Falsification through Prediction | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| INP39 | Reflected XSS | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| INP40 | Stored XSS | ABGEDECKT | cross-site-scripting | XSS-Variante (Kontext/Kodierung); Threagile bewertet XSS pro Web-Asset, nicht pro Variante | – |
| AC17 | Session Hijacking - ServerSide | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| AC18 | Session Hijacking - ClientSide | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| INP41 | Argument Injection | TAG-BASIERT | - | Ausführen von OS-Befehlen ist nicht modelliert | Tag executes-os-commands auf Asset mit custom_developed_parts und eingehenden Links. Regel-ID-Vorschlag: os-command-injection |
| AC19 | Reusing Session IDs (aka Session Replay) - ServerSide | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| AC20 | Reusing Session IDs (aka Session Replay) - ClientSide | TAG-BASIERT | - | Sitzungsverwaltung (Session-Tokens, Timeouts, Cookies) ist nicht im Modell | Tag session-tokens auf Asset (Technologie web-application/web-server/application-server); Regel gibt ein Risiko pro Asset aus. Gegenmaßnahmen über Risk-Tracking. Regel-ID-Vorschlag: weak-session-management |
| AC21 | Cross Site Request Forgery | ABGEDECKT | cross-site-request-forgery | CSRF | – |
| DS06 | Data Leak | NICHT ABBILDBAR | - | Datenklassifikation pro Datenfluss (hasDataLeaks) hat keine Entsprechung; Threagile leitet Asset-CIA aus den Daten ab | – |
| DR01 | Unprotected Sensitive Data | ABGEDECKT | unencrypted-communication (+ unencrypted-asset bei DR01) | unverschlüsselte/ungeschützte Kommunikation; TLS-Version/Zertifikatsprüfung nicht modelliert | – |
| AC22 | Credentials Aging | TAG-BASIERT | - | Lebensdauer/Art von Zugangsdaten ist kein Datenasset-Attribut | Tags auf Datenasset: credentials, credentials-long-lived, credentials-hardcoded; übertragen über Link zu Asset im Scope. Regel-ID-Vorschlag: credentials-lifecycle-weakness |
| AC23 | Credentials Disclosure | TAG-BASIERT | - | Lebensdauer/Art von Zugangsdaten ist kein Datenasset-Attribut | Tags auf Datenasset: credentials, credentials-long-lived, credentials-hardcoded; übertragen über Link zu Asset im Scope. Regel-ID-Vorschlag: credentials-lifecycle-weakness |
| AC24 | Use of hardcoded credentials | TAG-BASIERT | - | Lebensdauer/Art von Zugangsdaten ist kein Datenasset-Attribut | Tags auf Datenasset: credentials, credentials-long-lived, credentials-hardcoded; übertragen über Link zu Asset im Scope. Regel-ID-Vorschlag: credentials-lifecycle-weakness |
| LLM01 | Direct Prompt Injection | PORTIERBAR | `llm-prompt-injection` (neu, umgesetzt) | Technologie ai existiert (Attribut ai) | Asset mit Technologie ai, das eingehende Links von Assets in anderer Trust-Boundary, aus dem Internet oder von menschlichen Clients hat; Impact aus Integrität/Vertraulichkeit. Eine Regel für Prompt-Injection und Jailbreak. Regel-ID-Vorschlag: llm-prompt-injection |
| LLM02 | Indirect Prompt Injection via Retrieved Content | TAG-BASIERT | - | RAG-Nutzung nicht modelliert | Tag rag auf Asset mit Technologie ai. Regel-ID-Vorschlag: llm-indirect-prompt-injection |
| LLM03 | Sensitive Data Leakage to Third-Party Provider | PORTIERBAR | `ai-sensitive-data-exposure` (neu, umgesetzt) | Technologie ai, Trust-Boundary-Typ und Datenvertraulichkeit sind modelliert | Asset mit Technologie ai, das Datenassets ab Vertraulichkeit confidential verarbeitet und in einer Trust-Boundary vom Typ network-cloud-provider liegt oder ausgehende Links/Antworten in eine weniger vertrauenswürdige Boundary hat. Eine Regel. Regel-ID-Vorschlag: ai-sensitive-data-exposure |
| LLM04 | Training Data Poisoning | TAG-BASIERT | - | Fine-Tuning nicht modelliert | Tag fine-tuning auf Asset mit Technologie ai. Regel-ID-Vorschlag: llm-training-data-poisoning |
| LLM05 | Excessive Agency via Unauthorized Tool Use | TAG-BASIERT | - | Agentenfähigkeiten/Codeausführung von KI-Assets nicht modelliert | Tags ai-agent bzw. executes-code auf Asset mit Technologie ai. Regel-ID-Vorschlag: llm-excessive-agency |
| LLM06 | Arbitrary Code Execution via LLM Agent | TAG-BASIERT | - | Agentenfähigkeiten/Codeausführung von KI-Assets nicht modelliert | Tags ai-agent bzw. executes-code auf Asset mit Technologie ai. Regel-ID-Vorschlag: llm-excessive-agency |
| LLM07 | Jailbreaking and Safety Bypass | PORTIERBAR | `llm-prompt-injection` (neu, umgesetzt) | Technologie ai existiert (Attribut ai) | Asset mit Technologie ai, das eingehende Links von Assets in anderer Trust-Boundary, aus dem Internet oder von menschlichen Clients hat; Impact aus Integrität/Vertraulichkeit. Eine Regel für Prompt-Injection und Jailbreak. Regel-ID-Vorschlag: llm-prompt-injection |
| LLM08 | Sensitive Information Disclosure Through Output | PORTIERBAR | `ai-sensitive-data-exposure` (neu, umgesetzt) | Technologie ai, Trust-Boundary-Typ und Datenvertraulichkeit sind modelliert | Asset mit Technologie ai, das Datenassets ab Vertraulichkeit confidential verarbeitet und in einer Trust-Boundary vom Typ network-cloud-provider liegt oder ausgehende Links/Antworten in eine weniger vertrauenswürdige Boundary hat. Eine Regel. Regel-ID-Vorschlag: ai-sensitive-data-exposure |
| LLM09 | Untrusted Tool Launch Configuration | TAG-BASIERT | - | Tool-Konfiguration von Agenten nicht modelliert | Tag uses-external-tools auf Asset mit Technologie ai. Regel-ID-Vorschlag: untrusted-tool-launch |

## 4. Fehlerhafte oder fragwürdige pytm-Bedingungen

Beurteilung allein anhand `condition` im JSON (siehe Grenze oben):

| SID | Befund |
|---|---|
| AC10 | `target.checkTLSVersion(target.inputs)` setzt eine Methode am Zieltyp Server voraus; im Snapshot nicht nachprüfbar. |
| AC22 | Überschneidet sich mit AC23/AC24 (HARDCODED in AC22 und AC24). |
| CR01 | `usesVPN`/`usesSessionTokens` sind Dataflow-Attribute, Ziel ist aber auch `Server` – Attribut ggf. nicht für den Zieltyp definiert. |
| CR02 | Wie CR01 (Attribute für Zieltyp Dataflow/Server gemischt, `protocol` für Server fraglich). |
| CR03 | Dictionary-Angriff setzt vorhandene Passwort-Authentifizierung voraus; Bedingung feuert bei fehlender Authentifizierung (`implementsAuthenticationScheme is False`). |
| CR05 | `usesEncryptionAlgorithm != 'RSA' and != 'AES'` stuft alle anderen Verfahren (z. B. ChaCha20, ECC) als schwach ein. |
| CR06 | `target.protocol != 'HTTPS'` ist für alle Nicht-HTTP(S)-Protokolle wahr (z. B. SSH); zu breit. |
| DE03 | `… or target.usesVPN is False` feuert für jeden Datenfluss ohne VPN, auch bei HTTPS/Verschlüsselung (zu breit). |
| DS02 | Bedingung nur `environment == 'Production'` – keine Schwachstellenbedingung. |
| INP05 | Ziel `Server`, thematisch Datenbank/SQL; Bedingung enthält keinen SQL-Bezug. |
| INP09 | Bedingung prüft kein LDAP-Protokoll/-Ziel (`controls.validatesInput` allein) – feuert für jeden Server. |
| INP16 | Bedingung prüft weder PHP noch Include-Funktion – feuert für jeden Server. |
| INP19 | Invertierte Logik: `usesXMLParser is False or disablesDTD is False` feuert gerade, wenn KEIN XML-Parser genutzt wird. |
| INP21 | Invertierte Logik wie INP19 (`usesXMLParser is False or …`). |
| INP22 | Invertierte Logik wie INP19 (`usesXMLParser is False or …`). |
| LLM09 | `validatesToolLaunchConfig` liegt direkt am Target, alle anderen Kontrollen unter `target.controls.*` – inkonsistent. |

Hinweis: Mehrere SIDs sind inhaltliche Duplikate mit identischer Bedingung (z. B. INP13/INP31/INP41, XSS-Familie); sie werden hier in je einer Threagile-Regel zusammengefasst.

## 5. Priorisierte Liste der PORTIERBAR-Regeln

Zusammengefasst zu 11 Threagile-Regeln (Maximum 25). Reihenfolge nach Nutzen (Verbreitung der Technologie im Modell, Eindeutigkeit der Bedingung, geringe Fehlalarmrate):

| Prio | Regel-ID (Vorschlag) | pytm-SIDs | Kurzbedingung | Aufwand |
|---|---|---|---|---|
| 1 | `http-request-smuggling` | INP04, INP36, INP37 | Proxy/LB/Gateway/WAF → Web-/App-Server über http(s) | gering |
| 2 | `mail-command-injection` | INP15 | Link auf mail-server per smtp/imap/pop3, Quelle eigenentwickelt/Endnutzer | gering |
| 3 | `missing-clickjacking-protection` | INP20 | web_application, erreicht von Mensch-Client über http(s) | gering |
| 4 | `shared-datastore-tampering` | AC02 | Datastore mit schreibenden Links aus ≥ 2 Trust-Boundaries | mittel |
| 5 | `xml-entity-expansion-dos` | DO03, DO04, DO05, INP22, INP34 | xml/SOAP-Asset von außerhalb der Boundary erreichbar | mittel |
| 6 | `llm-prompt-injection` | LLM01, LLM07 | Technologie ai mit Zugriff aus Internet/anderer Boundary/Mensch | mittel |
| 7 | `ai-sensitive-data-exposure` | LLM03, LLM08 | ai verarbeitet ≥ confidential, Cloud-Boundary oder Ausgang in schwächere Boundary | mittel |
| 8 | `client-reverse-engineering` | HA02, HA04 | mobile-app/desktop/iot-device mit sensiblen Daten/eigenem Code | gering |
| 9 | `audit-log-manipulation` | DE04 | monitoring-Asset mit schreibendem Zugriff aus anderer Boundary | mittel |
| 10 | `xml-schema-poisoning` | AC04 | xml-Link mit authorization none | gering (niedriger Nutzen) |
| 11 | `json-hijacking` | SC01 | – | Empfehlung: nicht portieren (veraltet) |

TAG-BASIERTE Regeln (12 Vorschläge, Tags siehe Tabelle) sind bewusst nicht Teil der Liste; sie erzeugen nur Risiken, wenn Modellierer Tags setzen, und können in einer späteren Runde folgen (Vorschlag: `weak-session-management`, `buffer-overflow-risk`, `os-command-injection`).

## 6. Offene Entscheidungen

- Zusammenfassung mehrerer SIDs je Regel (siehe oben) – Vorschlag so umsetzen.
- Regeln 6/7 (KI) hängen an der Technologie `ai`; Fehlalarmrate hängt von der Modellierung ab.

## 7. Umsetzungsstand

Umgesetzt (Branch `claude/modest-babbage-1pgomq`, je ein Commit `feat(rules): add <id> (ported from pytm <SID>)`), jeweils mit Positiv- und Negativtests in `pkg/risks/builtin/*_rule_test.go`:

| Prio | Regel-ID | pytm-SIDs |
|---|---|---|
| 1 | `http-request-smuggling` | INP04, INP36, INP37 |
| 2 | `mail-command-injection` | INP15 |
| 3 | `missing-clickjacking-protection` | INP20 |
| 4 | `shared-datastore-tampering` | AC02 |
| 5 | `xml-entity-expansion-dos` | DO03, DO04, DO05, INP22, INP34 |
| 6 | `llm-prompt-injection` | LLM01, LLM07 |
| 7 | `ai-sensitive-data-exposure` | LLM03, LLM08 |
| 8 | `client-reverse-engineering` | HA02, HA04 |
| 9 | `audit-log-manipulation` | DE04 |
| 10 | `xml-schema-poisoning` | AC04 |

Nicht umgesetzt: `json-hijacking` (SC01, veraltetes Angriffsmuster) sowie alle TAG-BASIERTEN Vorschläge. Bestehende Regeln wurden nicht verändert.

Review-Nachtrag: Der Titel von `http-request-smuggling` nennt keinen Forwarder mehr (die Auswahl hing von der Map-Reihenfolge ab), und `xml-entity-expansion-dos` bewertet den Impact nach der höchsten Availability von Asset und verarbeiteten Daten.

### Kurzbericht: Anschlag auf dem Beispielmodell
Golden-Diff gegen die Baseline (normalisiert): 63 → 68 Risiken – nur Zusätze; alle bestehenden Risiken, Technical Assets und beide Diagramme unverändert.

| Regel | Treffer im Beispielmodell |
|---|---|
| `http-request-smuggling` | 2 (`apache-webserver`, `marketing-cms` hinter dem Load Balancer) |
| `xml-entity-expansion-dos` | 1 (`erp-system`, akzeptiert XML, erreichbar von anderer Boundary) |
| übrige 7 Regeln | 0 – das Beispielmodell enthält keine Mail-Links, KI-Assets, Mobile-/Desktop-/IoT-Clients, Monitoring-Assets, schreibenden Mehrfachzugriffe auf Datastores über Boundaries hinweg bzw. XML-Links ohne Autorisierung |
| `missing-clickjacking-protection` | 0 – Web-Anwendungen werden im Beispiel nicht von einem als Mensch-Client markierten Asset erreicht, das die Bedingung erfüllt |

Die nicht angeschlagenen Regeln sind ausschließlich durch Unit-Tests belegt. Beim Lauf traten keine Panics auf.
