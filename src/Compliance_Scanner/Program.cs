// =============================================================================
//  Compliance_Scanner — C# Implementation
//  Usage:  ./Compliance_Scanner <path/to/policy.yaml>
//          ./Compliance_Scanner -h | --help
// =============================================================================

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Compliance_Scanner;

// ── Helper Functions ──────────────────────────────────────────────────────

static SCAPolicy LoadPolicy(string path, IDeserializer deserializer)
{
    string yaml = File.ReadAllText(path);
    return deserializer.Deserialize<SCAPolicy>(yaml);
}

static string GetPlatform() =>
    OperatingSystem.IsWindows() ? "Windows" :
    OperatingSystem.IsMacOS() ? "macOS" : "Linux";

static string GetSafeHostName()
{
    string hostName = Environment.MachineName;
    char[] invalidChars = Path.GetInvalidFileNameChars();
    string safe = new(hostName
        .Select(c => invalidChars.Contains(c) ? '_' : c)
        .ToArray());

    return string.IsNullOrWhiteSpace(safe) ? "unknown-host" : safe;
}

static string GetDefaultOutputRoot()
{
    string? reportsDir = Environment.GetEnvironmentVariable("REPORTS_DIR");
    if (!string.IsNullOrWhiteSpace(reportsDir))
        return reportsDir;

    return "results";
}

static string BuildArtifactPath(string outputRoot, string fileName)
{
    return Path.Combine(outputRoot, fileName);
}

static void TrySetUnixMode(string path, UnixFileMode mode)
{
    if (OperatingSystem.IsWindows())
        return;

    try
    {
        File.SetUnixFileMode(path, mode);
    }
    catch
    {
        // Best effort: permissions may be controlled by mount options or filesystem support.
    }
}

static void EnsureOutputDirectory(string outputRoot)
{
    Directory.CreateDirectory(outputRoot);
    TrySetUnixMode(outputRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                               UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
}

static void EnsureParentDirectory(string filePath)
{
    string? directory = Path.GetDirectoryName(Path.GetFullPath(filePath));
    if (!string.IsNullOrWhiteSpace(directory))
        EnsureOutputDirectory(directory);
}

static void TightenReportPermissions(params string?[] filePaths)
{
    foreach (string? filePath in filePaths)
    {
        if (!string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath))
            TrySetUnixMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                     UnixFileMode.GroupRead | UnixFileMode.OtherRead);
    }
}

// ── Requirements check (silent) ──────────────────────────────────────────────

static bool RequirementsMet(SCAPolicy policy)
{
    if (policy.Requirements is null) return true;
    Check reqCheck = new()
    {
        Id = 0,
        Title = policy.Requirements.Title,
        Name = policy.Requirements.Name,
        Condition = policy.Requirements.Condition,
        Rules = policy.Requirements.Rules
    };
    return RuleChecker.EvaluateCheck(reqCheck, policy.Variables).Status == CheckStatus.Passed;
}

// ── Directory Scan ────────────────────────────────────────────────────────────

static int ScanDirectory(string dirPath, IReporter reporter, IDeserializer deserializer, ComplianceReport report)
{
    List<string> files = Directory.GetFiles(dirPath, "*.yml")
        .Concat(Directory.GetFiles(dirPath, "*.yaml"))
        .OrderBy(f => f)
        .ToList();

    if (files.Count == 0)
    {
        reporter.PrintNoPolicesFound(dirPath);
        report.Errors.Add($"No .yml / .yaml files found in {dirPath}");
        return 1;
    }

    reporter.PrintDiscoveryHeader(dirPath, files.Count);

    // ── Check requirements for each file ──────────────────────────────────────
    List<string> applicable = new();

    foreach (string file in files)
    {
        string fileName = Path.GetFileName(file);
        SCAPolicy policy;
        try { policy = LoadPolicy(file, deserializer); }
        catch (Exception ex)
        {
            report.Discovery.Add(new(Path.GetFullPath(file), false, "parse error", ex.Message));
            report.Errors.Add($"Failed to parse {fileName}: {ex.Message}");
            reporter.PrintRequirementCheckLine(fileName, false, "parse error — skipped");
            continue;
        }

        if (RequirementsMet(policy))
        {
            string note = policy.Requirements is null ? "no requirements" : "requirements met";
            reporter.PrintRequirementCheckLine(fileName, true, note);
            applicable.Add(file);
            report.Discovery.Add(new(Path.GetFullPath(file), true, note));
        }
        else
        {
            reporter.PrintRequirementCheckLine(fileName, false, "requirements not met — skipped");
            report.Discovery.Add(new(Path.GetFullPath(file), false, "requirements not met"));
        }
    }

    if (applicable.Count == 0)
    {
        reporter.PrintError("No applicable policies found for this system.");
        report.Errors.Add("No applicable policies found for this system.");
        return 1;
    }

    reporter.PrintApplicablePoliciesLine(applicable.Count);

    // ── Run each applicable policy ────────────────────────────────────────────
    int overallFailed = 0;
    for (int i = 0; i < applicable.Count; i++)
    {
        reporter.PrintPolicyExecutionHeader(i + 1, applicable.Count, Path.GetFileName(applicable[i]));
        int result = ScanCommand(applicable[i], reporter, deserializer, report);
        if (result != 0) overallFailed++;
    }

    reporter.PrintDirectoryScanComplete(applicable.Count, overallFailed);

    return overallFailed > 0 ? 1 : 0;
}

// ── Scan Command ─────────────────────────────────────────────────────────

static int ScanCommand(string policyPath, IReporter reporter, IDeserializer deserializer, ComplianceReport report)
{
    var policyReport = new PolicyReport { Path = Path.GetFullPath(policyPath) };
    report.Policies.Add(policyReport);
    if (!File.Exists(policyPath))
    {
        policyReport.Error = $"Policy file not found: {policyPath}";
        reporter.PrintError(policyReport.Error);
        return 1;
    }

    SCAPolicy policy;
    try
    {
        policy = LoadPolicy(policyPath, deserializer);
    }
    catch (Exception ex)
    {
        policyReport.Error = $"Parsing policy YAML: {ex.Message}";
        reporter.PrintError(policyReport.Error);
        return 1;
    }

    policyReport.Policy = policy.Policy;
    reporter.PrintPolicyHeader(policy, GetPlatform());

    List<int> unnamedChecks = policy.CheckIdsWithoutDisplayTitle();
    if (unnamedChecks.Count > 0)
        reporter.PrintWarning($"{unnamedChecks.Count} check(s) have no title or name (ids: {string.Join(", ", unnamedChecks.Take(10))}{(unnamedChecks.Count > 10 ? ", …" : "")})");

    // ── Requirements ─────────────────────────────────────────────────────────────

    if (policy.Requirements is not null)
    {
        Check reqCheck = new()
        {
            Id = 0,
            Title = policy.Requirements.Title,
            Name = policy.Requirements.Name,
            Description = policy.Requirements.Description,
            Condition = policy.Requirements.Condition,
            Rules = policy.Requirements.Rules
        };

        CheckResult reqResult = RuleChecker.EvaluateCheck(reqCheck, policy.Variables);
        reporter.PrintRequirementsSection(reqCheck, policy.Variables, reqResult);
        policyReport.Requirements = CheckEvidence.From(reqCheck, reqResult);

        if (reqResult.Status != CheckStatus.Passed)
        {
            policyReport.Status = "requirementsNotMet";
            return 1;
        }
    }

    // ── Run checks ────────────────────────────────────────────────────────────────

    int totalPassed = 0, totalFailed = 0, totalInvalid = 0;
    List<ScanCheckResult> checkResults = new();

    foreach (Check check in policy.Checks)
    {
        reporter.PrintCheckHeader(check);

        // ── Parse & explain rules before execution ──────────────────────────────
        List<ParsedRule> parsedRules = check.Rules
            .Select(rule => RuleParser.Parse(rule, policy.Variables))
            .ToList();

        reporter.PrintRuleExplanations(parsedRules, check, policy.Variables);

        // ── Execute ──────────────────────────────────────────────────────────────
        CheckResult result = RuleChecker.EvaluateCheck(check, policy.Variables);
        reporter.PrintRuleResults(result.RuleResults);
        reporter.PrintCheckResult(check, result, totalPassed, totalFailed);
        policyReport.Checks.Add(CheckEvidence.From(check, result));

        checkResults.Add(new ScanCheckResult
        {
            Id = check.Id,
            Title = check.DisplayTitle,
            Status = result.Status,
            Reason = result.Reason
        });

        if (result.Status == CheckStatus.Passed)
            totalPassed++;
        else if (result.Status == CheckStatus.Failed)
            totalFailed++;
        else if (result.Status == CheckStatus.Invalid)
            totalInvalid++;
    }

    // ── Summary ───────────────────────────────────────────────────────────────────

    reporter.PrintScanSummary(totalPassed, totalFailed, totalInvalid, checkResults);

    policyReport.Status = totalFailed > 0 ? "failed" : totalInvalid > 0 ? "invalid" : "passed";
    return totalFailed > 0 ? 1 : 0;
}

// ── Main Entry Point ─────────────────────────────────────────────────────────

OutputLevel outputLevel = OutputLevel.Standard;
string? logFile = null;
string? reportFile = null;
string outputRoot = GetDefaultOutputRoot();
string? target = null;

// ── Phase 1: Early argument scanning for --write-config and --config ─────────
string? configPath = null;
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--write-config")
    {
        // Determine output path for config template
        string writePath = (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
            ? args[++i]
            : "config.yml";

        var tempConsoleReporter = new ConsoleReporter();
        try
        {
            ConfigLoader.WriteTemplate(writePath, tempConsoleReporter);
        }
        catch (Exception ex)
        {
            tempConsoleReporter.PrintError(ex.Message);
            return 1;
        }
        return 0;
    }

    if ((args[i] == "-c" || args[i] == "--config") && i + 1 < args.Length)
    {
        configPath = args[++i];
    }
}

// ── Phase 2: Load configuration file (if it exists) ───────────────────────────
var tempReporter = new ConsoleReporter();
ScannerConfig loadedConfig;
try
{
    loadedConfig = ConfigLoader.LoadConfig(configPath, tempReporter);
}
catch (Exception ex)
{
    tempReporter.PrintError(ex.Message);
    return 1;
}

// Apply loaded config values as defaults for CLI arguments
try
{
    if (loadedConfig.OutputLevel.HasValue)
        outputLevel = loadedConfig.OutputLevel.Value;
    if (loadedConfig.OutputDir is not null)
        outputRoot = loadedConfig.OutputDir;
    if (loadedConfig.LogFile is not null)
        logFile = loadedConfig.LogFile;
    if (loadedConfig.ReportFile is not null)
        reportFile = loadedConfig.ReportFile;

}
catch (ArgumentException ex)
{
    tempReporter.PrintError(ex.Message);
    return 1;
}

// ── Phase 3: Parse CLI arguments (overrides config file values) ──────────────
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "-h":
        case "--help":
            new ConsoleReporter().PrintHelp();
            return 0;
        case "--display-details":
            outputLevel = OutputLevel.Detailed;
            break;
        case "--no-details":
            outputLevel = OutputLevel.Compact;
            break;
        case "--output-dir":
            if (i + 1 < args.Length)
                outputRoot = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --output-dir requires a directory path argument.");
                return 1;
            }
            break;
        case "-l":
        case "--log":
            if (i + 1 < args.Length)
                logFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: -l/--log requires a file path argument.");
                return 1;
            }
            break;
        case "--json":
        case "-r":
        case "--report":
            if (i + 1 < args.Length)
                reportFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --json/-r/--report requires a file path argument.");
                return 1;
            }
            break;
        case "-c":
        case "--config":
            // Already handled in Phase 1, just skip here
            if (i + 1 < args.Length) i++;
            break;
        case "--write-config":
            // Already handled in Phase 1, just skip here
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                i++;
            break;
        default:
            if (args[i].StartsWith("-"))
            {
                Console.Error.WriteLine($"Error: unknown option '{args[i]}'. Use --help for supported options.");
                return 1;
            }
            if (target is null)
                target = args[i];
            else
            {
                Console.Error.WriteLine($"Error: unexpected argument '{args[i]}'.");
                return 1;
            }
            break;
    }
}

if (target is null)
{
    new ConsoleReporter().PrintHelp();
    return 0;
}

string hostName = GetSafeHostName();
logFile ??= BuildArtifactPath(outputRoot, $"hardening-{hostName}.log");
reportFile ??= BuildArtifactPath(outputRoot, $"hardening-{hostName}.json");

var report = new ComplianceReport { Target = Path.GetFullPath(target) };
int exitCode = 1;

try
{
    if (!string.Equals(Path.GetExtension(reportFile), ".json", StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("The report path must have a .json extension.");
    if (string.Equals(Path.GetFullPath(logFile), Path.GetFullPath(reportFile),
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        throw new ArgumentException("Log and JSON report must use different file paths.");

    EnsureOutputDirectory(outputRoot);
    EnsureParentDirectory(logFile);
    EnsureParentDirectory(reportFile);

    using var fileReporter = new FileReporter(logFile);
    IReporter reporter = new CompositeReporter(new ConsoleReporter(outputLevel), fileReporter);
    IDeserializer deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    try
    {
        exitCode = Directory.Exists(target)
            ? ScanDirectory(target, reporter, deserializer, report)
            : ScanCommand(target, reporter, deserializer, report);
        if (report.Errors.Count > 0) exitCode = 1;
    }
    catch (Exception ex)
    {
        report.Errors.Add(ex.Message);
        reporter.PrintError($"Scan failed: {ex.Message}");
        exitCode = 1;
    }

    report.ExitCode = exitCode;
    report.CompletedAtUtc = DateTimeOffset.UtcNow;
    string json = report.ToJson();
    File.WriteAllText(reportFile, json);
    Console.WriteLine(json);
    reporter.PrintInfo($"JSON report: {Path.GetFullPath(reportFile)}");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    exitCode = 1;
}
finally
{
    TightenReportPermissions(logFile, reportFile);
}

return exitCode;
