# AGENTS.md — Project Instructions & Guidelines

## 1. Project Overview
`IMPAKT_Security_Scanner` is a multi-project .NET 10 (`net10.0`) repository containing standalone, single-purpose C# console applications for security compliance scanning and secure report transport.

### Repository Layout
```text
IMPAKT_Security_Scanner.sln
Directory.Build.props          # Shared settings: net10.0, Nullable=enable, ImplicitUsings=enable
global.json                    # Pins .NET SDK 10.0.100 (rollForward: latestFeature)
build.sh / build.ps1           # Release build & self-contained single-file publish scripts
src/
  Compliance_Scanner/          # Wazuh SCA YAML compliance scanner
  Sftp_Uploader/               # Standalone SFTP report uploader with host-key verification
tests/
  IMPAKT_Security_Scanner.Tests/ # xUnit test suite covering all applications
tools/                         # Helper scripts (split_cis_dc_ms.py: CIS Windows Server benchmark -> member server / DC variants)
```

---

## 2. General Workflow & Environment Rules
- **Do not commit:** Never run `git commit`. The user validates all changes and creates commits manually.
- **Build & test after changes:** Always run `dotnet build IMPAKT_Security_Scanner.sln` and `dotnet test IMPAKT_Security_Scanner.sln` after modifying code, project files, or policies. Ensure zero build warnings/errors and all tests pass.
- **Docker:** Available as `docker` and `docker compose` (the engine may need to be started by the user).
- **Python:** Always use `python3` for Python commands.
- **Never commit secrets, external CIS policies, or artifacts:**
  - Keep `config.yml`, `sftp-config.yml`, `*.pem`, `*.key`, `results/`, and `artifacts/` untracked.
  - CIS benchmark YAML files are owned by Wazuh and must not be committed to this repository (`src/Compliance_Scanner/Policies/CIS/*` and `src/Compliance_Scanner/Policies/cis_*.yml` are gitignored, except `CIS/README.md`).

---

## 3. Architecture & Multi-Package Rules
- **Single-purpose executables:** Keep every console application under `src/<Application>/` independently buildable and publishable.
- **Strict decoupling:**
  - Scanners (`Compliance_Scanner` and any future scanners/collectors) must **never** reference `Sftp_Uploader` or `SSH.NET`.
  - Scanners only collect evidence and write local JSON reports and text logs; transport or downstream ingestion (e.g. ESB/Pipeline package) is handled as a separate step.
- **Adding a new console application:**
  1. Create `src/<AppName>/<AppName>.csproj` (`<OutputType>Exe</OutputType>`). Rely on `Directory.Build.props` for `TargetFramework`, `Nullable`, and `ImplicitUsings`.
  2. Add the project to `IMPAKT_Security_Scanner.sln` (`dotnet sln IMPAKT_Security_Scanner.sln add src/<AppName>/<AppName>.csproj`).
  3. Reference the project in `tests/IMPAKT_Security_Scanner.Tests/IMPAKT_Security_Scanner.Tests.csproj` and add unit tests.
  4. Include a concise `src/<AppName>/README.md` documenting CLI flags, YAML configuration, output format, and exit codes.
  5. `build.sh` and `build.ps1` automatically discover all `src/*/*.csproj` projects.
- **Shared code:** Avoid premature coupling between tools. If shared code becomes necessary (e.g., report envelope models, safe hostname resolution, file permission helpers), extract a dedicated class library (e.g., `src/IMPAKT.Common/`) rather than referencing one console app from another.

---

## 4. Configuration, Output & Exit Code Standards
- **Configuration is always YAML:**
  - Every application in this repository uses **YAML** (`YamlDotNet` with `UnderscoredNamingConvention`) for configuration files (`-c, --config <path.yml>` and `--write-config [path.yml]`).
  - CLI arguments always override YAML configuration values.
- **Output is always JSON (reports) + Text (logging):**
  - Scanners (`Compliance_Scanner`) output structured **JSON** only (written to a `.json` file and `stdout` for consumption by an ESB/Pipeline package).
  - All human-readable progress, banners, warnings, and operational diagnostics are written as **text logs** to `stderr` (`Console.Error`) and `.log` files (`-l, --log <path.log>` / `log_file`).
- **JSON serialization:**
  - Use `System.Text.Json` with `PropertyNamingPolicy = JsonNamingPolicy.CamelCase` and `WriteIndented = true`.
  - Include `schemaVersion` (`"1.0"`), `computerName`, `operatingSystem`, and UTC timestamps (`DateTimeOffset.UtcNow`).
- **Output paths & permissions:**
  - Default output directory must respect the `REPORTS_DIR` environment variable and fall back to `./results/`.
  - Sanitize `Environment.MachineName` (replace `Path.GetInvalidFileNameChars()` with `_`) when constructing default report/log filenames.
  - On Unix (Linux/macOS), restrict permissions on output directories (`750`) and generated report/log files (`644`).
- **Exit codes:**
  - `0`: Success (`Compliance_Scanner`: all applicable checks passed with no errors; `Sftp_Uploader`: all files uploaded or `--dry-run` validated).
  - `1`: Any failed compliance check, unmet policy requirement, collection error, upload failure, or invalid CLI/config argument.

---

## 5. Cross-Platform, Security & Coding Standards
- **Supported targets:** Windows (`win-x64`), Linux (`linux-x64`), macOS (`osx-arm64`). Guard platform-specific logic (e.g., Windows Registry) with `OperatingSystem.IsWindows()`, `OperatingSystem.IsLinux()`, and `OperatingSystem.IsMacOS()`.
- **Culture invariance:** Always specify `CultureInfo.InvariantCulture` when parsing or formatting numbers, floats, and timestamps (`double.TryParse`, `int.TryParse`, etc.). Target hosts frequently run under `nl-NL` (comma decimal separator) while YAML policies and CLI outputs use `.`.
- **Safe process execution:**
  - Always use `ProcessStartInfo.ArgumentList` (and Base64 `-EncodedCommand` for PowerShell) instead of string-interpolated shell command lines so embedded quotes or special characters never break execution.
  - Always enforce timeouts when spawning external processes, read `StandardOutput` and `StandardError` asynchronously before `WaitForExit` to avoid deadlocks, kill the process tree (`process.Kill(entireProcessTree: true)`) on timeout, and treat timed-out compliance rules as `Invalid`.
  - Force `LC_ALL=C` and `LANG=C` when invoking Linux/macOS CLI tools so output parsing does not break on localized OS installations.
- **Read-only scanning:**
  - Scanners and collectors must not alter system state, install updates, or refresh remote package manager metadata (`apt update`, `dnf makecache`).
- **Secure transport (`Sftp_Uploader`):**
  - Never use unencrypted FTP; use SFTP (`SSH.NET`) with mandatory server host-key fingerprint verification (`SHA256:<base64>`).
  - Never accept passwords via CLI flags or config files; passwords may only be read from the `SFTP_PASS` environment variable (prefer SSH key authentication via `--key`).

---

## 6. Application Reference

### `src/Compliance_Scanner`
Evaluates system compliance against Wazuh SCA YAML policies.
- **Core components:**
  - `Program.cs`: CLI parsing, YAML config loading (`ScannerConfig`), policy discovery (`ScanDirectory`), and scan execution (`ScanCommand`).
  - `Models.cs`: YAML models (`SCAPolicy`, `PolicyMetadata`, `Requirements`, `Check`, `PolicyVariables`) and enums (`CheckStatus`, `CheckCondition`, `OutputLevel`).
  - `RuleParser.cs`: Parses Wazuh SCA rules (`f:`, `d:`, `p:`, `c:`, `r:`), negation (`!` / `not `), content matching (`->`), regex (`r:`), culture-invariant numeric comparisons (`n:<regex> compare <op> <val>`), and `&&` conditions.
  - `RuleChecker.cs`: Evaluates parsed rules against the OS and aggregates check status using `all`, `any`, or `none` condition logic.
  - `JsonReport.cs`: Serializable JSON report (`ComplianceReport`, `PolicyReport`, `CheckEvidence`, `RuleEvidence`).
  - `IReporter.cs` / `BaseReporter.cs` / `ConsoleReporter.cs` / `FileReporter.cs` / `CompositeReporter.cs`: Text logging to `stderr` and `.log` file.

### `src/Sftp_Uploader`
Uploads generated report files to an SFTP server.
- **Core components:**
  - `SftpConfig.cs`: YAML configuration (`host`, `port`, `user`, `key_path`, `host_key_sha256`, `remote_path`, `log_file`), template generation, and validation.
  - `SftpUploader.cs`: Connects via `SSH.NET`, verifies `HostKeyReceived` against `HostKeySha256`, ensures remote directory exists, and uploads files with text logging.

---

## 7. Build, Test & Publish Commands
```sh
# Build & test entire solution
dotnet build IMPAKT_Security_Scanner.sln --configuration Release
dotnet test IMPAKT_Security_Scanner.sln --configuration Release

# Run individual applications
dotnet run --project src/Compliance_Scanner -- --output-dir results/compliance src/Compliance_Scanner/Policies/
dotnet run --project src/Sftp_Uploader -- --config sftp-config.yml --directory results/compliance --dry-run

# Publish self-contained single-file binaries (win-x64, linux-x64, osx-arm64)
./build.sh win-x64
./build.sh linux-x64 Sftp_Uploader
```
