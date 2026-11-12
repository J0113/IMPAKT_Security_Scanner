# Compliance_Scanner

Console-applicatie voor compliancechecks met Wazuh SCA YAML-policies. Ondersteunt Windows, Linux en macOS.

```sh
dotnet run --project src/Compliance_Scanner -- --help
dotnet run --project src/Compliance_Scanner -- --write-config config.yml
dotnet run --project src/Compliance_Scanner -- --output-dir results/compliance src/Compliance_Scanner/Policies/
```

Een bestand voert één policy uit; een map selecteert toepasselijke `.yaml`/`.yml`-policies uit die map. Iedere scan schrijft één JSON-rapport naar `hardening-<host>.json` in `REPORTS_DIR` of `./results/`. Gebruik `--output-dir` voor een andere map of `--json <pad.json>` (`-r`/`--report`) voor een specifiek rapportpad. YAML-configuratie gebruikt `report_file`.

Hetzelfde JSON-document verschijnt op `stdout` (voor verwerking door een ESB/Pipeline). Diagnostische consolelogging gaat naar `stderr` en een gedetailleerd tekstlog naar `hardening-<host>.log` (ander pad via `--log`/`log_file`).

Het JSON-document bevat `schemaVersion`, scanner, host, besturingssysteem, doelpad, UTC-tijden, exitcode, policyselectie (`discovery`), uitgevoerde policies en samenvattingen. Per policy zijn metadata, requirements en checkresultaten beschikbaar. Checks bevatten beschrijving, rationale, remediation, conditie, status, reden en de afzonderlijke regels met uitvoerdetails. Statuswaarden zijn leesbare strings, zoals `passed`, `failed` en `invalid`. Bij een mapscan staan alle uitgevoerde policies in één rapport; niet-toepasselijke en onleesbare policies staan in `discovery`. Ook bij scan- of policyfouten wordt JSON geschreven als de uitvoerlocatie toegankelijk is.

## Policies

Policies volgen het Wazuh SCA-formaat. Checks en `requirements` ondersteunen zowel `title:` als `name:`. Als beide zijn ingevuld, toont het rapport `title:`. Een check zonder titel of naam geeft een waarschuwing.

Status `invalid` betekent dat een regel niet uitgevoerd kon worden (timeout, geen toegang, kapotte regel, niet-ondersteund platform). Een ontbrekend bestand, map of registerwaarde is gewoon `failed` (met `not` juist `passed`).

CIS Windows Server-benchmarks bestaan per OS als twee bestanden: `cis_win<jaar>_ms.yml` (member server) en `cis_win<jaar>_dc.yml` (Domain Controller). Een extra requirement op `ProductType` (`ServerNT` of `LanmanNT`) laat de scanner het juiste bestand kiezen. Maak ze uit het Wazuh-bestand met `python3 tools/split_cis_dc_ms.py cis_win2022.yml` en verwijder daarna het origineel. Het script zet ook geneste `c:powershell ...`-regels om naar directe PowerShell en stopt bij een onbekende vorm. De bestanden staan in `.gitignore`.

Rapportverzending gaat via de aparte `Sftp_Uploader`. CIS-benchmarks zijn eigendom van Wazuh en worden niet in deze repository meegeleverd; zie `Policies/CIS/README.md` voor de officiële Wazuh-bron.

Exitcodes: `0` bij een scan zonder gefaalde checks; `1` bij gefaalde checks, niet-gehaalde requirements of fouten, inclusief YAML-parsefouten tijdens policyselectie. Controleer policies vóór gebruik: commandoregels worden op het doelsysteem uitgevoerd met de rechten van de gebruiker.

Op Windows voert de scanner `c:`-regels uit als PowerShell-script. De scanner ondersteunt directe PowerShell en zet veelgebruikte Wazuh-vormen automatisch om, waaronder `powershell -NoProfile -Command "…"`, `powershell.exe …` met volledig pad of `%VARIABELE%`, `cmd /c powershell …` en `-EncodedCommand`. Met `--display-details` zie je de uitvoer per regel.
