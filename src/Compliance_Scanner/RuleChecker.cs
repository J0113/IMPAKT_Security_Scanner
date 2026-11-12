using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Compliance_Scanner;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// <summary>Result of evaluating a single rule string from a check's rules list.</summary>
public sealed record RuleResult(bool Passed, bool Invalid, string Detail);

/// <summary>Result of evaluating an entire check (all its rules + condition).</summary>
public sealed record CheckResult(
    CheckStatus             Status,
    string                  Reason,
    IReadOnlyList<RuleResult> RuleResults);

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

public static class RuleChecker
{
    private sealed class RuleCheckResult
    {
        public CheckStatus Status { get; set; }
        public string Detail { get; set; } = string.Empty;
    }

    // =========================================================================
    // Check evaluation  (applies condition: all / any / none)
    // =========================================================================

    public static CheckResult EvaluateCheck(Check check, PolicyVariables? variables)
    {
        List<RuleResult> results = check.Rules
            .Select(r => EvaluateRule(RuleParser.Parse(r, variables)))
            .ToList();

        bool hasInvalid = results.Any(r => r.Invalid);
        bool hasValidPass = results.Where(r => !r.Invalid).Any(r => r.Passed);
        bool hasValidFail = results.Where(r => !r.Invalid).Any(r => !r.Passed);
        int passCount = results.Count(r => r.Passed && !r.Invalid);
        int validCount = results.Count(r => !r.Invalid);

        // Evaluate based on condition type and whether there are invalid rules
        CheckCondition condType = check.ConditionEnum;
        CheckStatus status;
        string reason;

        if (condType == CheckCondition.Any)
        {
            // ANY: requires at least one rule to pass
            // If there's a valid pass, result is PASS (even with invalids)
            // If all valid rules fail (none pass), result is FAIL (proven outcome)
            // If all rules are invalid, result is INVALID (can't execute any)
            if (hasValidPass)
            {
                status = CheckStatus.Passed;
                reason = $"Condition 'ANY': at least one rule passed";
            }
            else if (validCount == 0)
            {
                // All rules are invalid → can't execute any
                status = CheckStatus.Invalid;
                reason = "Check invalid: all rules cannot be executed";
            }
            else
            {
                // All valid rules fail (none pass) → proven to fail
                status = CheckStatus.Failed;
                reason = $"Condition 'ANY': {passCount}/{validCount} rules passed";
            }
        }
        else if (condType == CheckCondition.All)
        {
            // ALL: requires all rules to pass
            // If there are any invalid rules, we can't confirm all pass → INVALID (unless proven to fail)
            // But a single definite failure overrides invalid (proves it will fail)
            bool allValidPass = !hasValidFail && validCount > 0;

            if (hasInvalid)
            {
                if (validCount == 0)
                {
                    // All rules are invalid → can't execute any
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: all rules cannot be executed";
                }
                else if (hasValidFail)
                {
                    // Have both invalid and valid fails → proven to fail
                    status = CheckStatus.Failed;
                    reason = $"Condition 'ALL': {passCount}/{validCount} rules passed";
                }
                else if (allValidPass)
                {
                    // All valid rules pass but some are invalid → can't confirm all pass
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: one or more rules cannot be executed";
                }
                else
                {
                    // All valid rules fail → definitely FAIL
                    status = CheckStatus.Failed;
                    reason = $"Condition 'ALL': {passCount}/{validCount} rules passed";
                }
            }
            else
            {
                // No invalid rules, use standard ALL logic
                bool allPassed = results.All(r => r.Passed);
                status = allPassed ? CheckStatus.Passed : CheckStatus.Failed;
                reason = $"Condition 'ALL': {passCount}/{validCount} rules passed";
            }
        }
        else if (condType == CheckCondition.None)
        {
            // NONE: requires all rules to fail (none pass)
            // If we know at least one rule passed (without being invalid), result is FAIL
            // If all rules are invalid, result is INVALID
            // If there are invalid rules but no passes, result is INVALID
            if (hasValidPass)
            {
                status = CheckStatus.Failed;
                reason = $"Condition 'NONE': {passCount}/{validCount} rules passed";
            }
            else if (hasInvalid)
            {
                // If all rules are invalid, can't execute any
                if (validCount == 0)
                {
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: all rules cannot be executed";
                }
                else
                {
                    // Some rules are invalid but valid ones all failed
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: one or more rules cannot be executed";
                }
            }
            else
            {
                bool nonePassed = results.All(r => !r.Passed);
                status = nonePassed ? CheckStatus.Passed : CheckStatus.Failed;
                reason = $"Condition 'NONE': {passCount}/{validCount} rules passed";
            }
        }
        else
        {
            // CheckCondition.Unknown — unrecognised YAML value
            status = CheckStatus.Invalid;
            reason = $"Unknown condition '{check.Condition}' — must be 'all', 'any', or 'none'";
        }

        return new CheckResult(status, reason, results);
    }

    // =========================================================================
    // Single rule evaluation (respects overall negation)
    // =========================================================================

    public static RuleResult EvaluateRule(ParsedRule rule)
    {
        // If the rule definition itself is invalid, return invalid status
        if (rule.Invalid)
        {
            return new RuleResult(false, true, $"Invalid rule: {rule.InvalidReason ?? "malformed"}");
        }

        RuleCheckResult checkResult = rule.Type switch
        {
            RuleType.File      => CheckFile(rule),
            RuleType.Directory => CheckDirectory(rule),
            RuleType.Process   => CheckProcess(rule),
            RuleType.Command   => CheckCommand(rule),
            RuleType.Registry  => CheckRegistry(rule),
            _                  => new RuleCheckResult { Status = CheckStatus.Failed, Detail = "Unknown rule type" }
        };

        // If the rule is invalid, propagate that status and don't apply negation
        if (checkResult.Status == CheckStatus.Invalid)
            return new RuleResult(false, true, checkResult.Detail);

        bool innerPassed = checkResult.Status == CheckStatus.Passed;
        bool finalPassed = rule.Negated ? !innerPassed : innerPassed;
        string finalDetail = rule.Negated ? $"[NEGATED] {checkResult.Detail}" : checkResult.Detail;
        return new RuleResult(finalPassed, false, finalDetail);
    }

    // =========================================================================
    // Rule type handlers
    // =========================================================================

    // ── File ─────────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckFile(ParsedRule rule)
    {
        // Handle comma-separated file paths (OR logic: stop at first existing)
        string[] files = rule.Target.Split(',');
        string? foundFile = null;

        foreach (string file in files)
        {
            string trimmedFile = file.Trim();
            if (File.Exists(trimmedFile))
            {
                foundFile = trimmedFile;
                break;
            }
        }

        if (foundFile is null)
        {
            // A missing file is a normal "condition not met" (Failed), not an error (Invalid)
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"File not found: {rule.Target}" };
        }

        if (!rule.HasContentCheck)
        {
            FileInfo info = new(foundFile);
            int lineCount;
            try
            {
                lineCount = File.ReadAllLines(foundFile).Length;
            }
            catch (UnauthorizedAccessException ex)
            {
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Permission denied reading '{foundFile}': {ex.Message}" };
            }
            catch (IOException ex)
            {
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"I/O error reading '{foundFile}': {ex.Message}" };
            }
            return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"File exists: {foundFile}  ({FormatBytes(info.Length)}, {lineCount} lines)" };
        }

        try
        {
            string content = File.ReadAllText(foundFile);
            var (matched, detail) = EvaluateContent(content, rule.ContentConditions, label: $"'{foundFile}'");
            return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
        }
        catch (UnauthorizedAccessException ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Permission denied reading '{foundFile}': {ex.Message}" };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Cannot read '{foundFile}': {ex.Message}" };
        }
    }

    // ── Directory ────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckDirectory(ParsedRule rule)
    {
        // Handle comma-separated directory paths (OR logic: stop at first existing)
        string[] dirs = rule.Target.Split(',');
        string? foundDir = null;

        foreach (string dir in dirs)
        {
            string trimmedDir = dir.Trim();
            if (Directory.Exists(trimmedDir))
            {
                foundDir = trimmedDir;
                break;
            }
        }

        if (foundDir is null)
        {
            // A missing directory is a normal "condition not met" (Failed), not an error (Invalid)
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Directory not found: {rule.Target}" };
        }

        if (!rule.HasContentCheck)
        {
            int count;
            try
            {
                count = Directory.GetFiles(foundDir).Length;
            }
            catch (UnauthorizedAccessException ex)
            {
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Permission denied reading '{foundDir}': {ex.Message}" };
            }
            catch (IOException ex)
            {
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"I/O error reading '{foundDir}': {ex.Message}" };
            }
            return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Directory exists: {foundDir}  ({count} files)" };
        }

        // For directory rules: match patterns against filenames (one per line).
        // Delegates to EvaluateContent() so AND (&&) conditions and negation work
        // consistently with file/command rules.
        try
        {
            string[] allFiles = Directory.GetFiles(foundDir);
            // Build content: one filename per line so EvaluateContent line logic applies
            string fileNames = string.Join("\n", allFiles.Select(Path.GetFileName));
            var (matched, detail) = EvaluateContent(fileNames, rule.ContentConditions, label: $"files in '{foundDir}'");
            return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
        }
        catch (UnauthorizedAccessException ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Permission denied reading '{foundDir}': {ex.Message}" };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Error checking directory '{foundDir}': {ex.Message}" };
        }
    }

    // ── Process ──────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckProcess(ParsedRule rule)
    {
        // Support both literal process names and regex patterns (p:r:PATTERN)
        if (rule.Target.StartsWith("r:", StringComparison.Ordinal))
        {
            // Regex pattern matching
            string pattern = rule.Target[2..];
            try
            {
                var regex = new System.Text.RegularExpressions.Regex(pattern);
                Process[] allProcs = Process.GetProcesses();
                var matchedProcs = allProcs.Where(p => regex.IsMatch(p.ProcessName)).ToArray();

                if (matchedProcs.Length > 0)
                {
                    string pids = string.Join(", ", matchedProcs.Select(p => p.Id));
                    string names = string.Join(", ", matchedProcs.Select(p => p.ProcessName).Distinct());
                    return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Process matching pattern '{pattern}' is running: {names}  (PID: {pids})" };
                }
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"No process matching pattern '{pattern}' found" };
            }
            catch (System.Text.RegularExpressions.RegexParseException ex)
            {
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Invalid regex pattern '{pattern}': {ex.Message}" };
            }
        }
        else
        {
            // Literal process name matching
            Process[] procs = Process.GetProcessesByName(rule.Target);
            bool running = procs.Length > 0;

            if (running)
            {
                string pids = string.Join(", ", procs.Select(p => p.Id));
                return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Process '{rule.Target}' is running  (PID: {pids})" };
            }
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Process '{rule.Target}' is not running  (0 instances found)" };
        }
    }

    // ── Command ──────────────────────────────────────────────────────────────
    public static int CommandTimeoutMilliseconds { get; set; } = 10_000;

    private static RuleCheckResult CheckCommand(ParsedRule rule)
    {
        try
        {
            ProcessStartInfo psi;
            if (OperatingSystem.IsWindows())
            {
                // Translate Wazuh command rules before passing the script to PowerShell.
                // Progress output would otherwise end up on stderr as CLIXML.
                string commandToRun = "$ProgressPreference = 'SilentlyContinue';" + Environment.NewLine
                    + WindowsCommand.ToPowerShellScript(rule.Target);
                string encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(commandToRun));

                psi = new ProcessStartInfo("powershell.exe")
                {
                    RedirectStandardInput  = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };
                psi.ArgumentList.Add("-NoLogo");
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-EncodedCommand");
                psi.ArgumentList.Add(encodedCommand);
            }
            else
            {
                psi = new ProcessStartInfo("/bin/sh")
                {
                    RedirectStandardInput  = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add(rule.Target);
                psi.Environment["LC_ALL"] = "C";
                psi.Environment["LANG"] = "C";
            }

            using Process proc = Process.Start(psi)!;
            // Rules have no input payload. Signal EOF instead of inheriting an open
            // scanner/test-host input pipe, which can leave PowerShell waiting in CI.
            proc.StandardInput.Close();
            // Read stdout and stderr concurrently to avoid deadlock when
            // either buffer fills, then combine them (many commands — like dscl —
            // write diagnostic output to stderr rather than stdout).
            Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = proc.StandardError.ReadToEndAsync();
            int timeoutMs = CommandTimeoutMilliseconds;
            bool streamsFinished = Task.WaitAll([stdoutTask, stderrTask], millisecondsTimeout: timeoutMs);
            bool procExited      = streamsFinished && proc.WaitForExit(Math.Min(5_000, timeoutMs));
            if (!streamsFinished || !procExited)
            {
                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { /* best effort */ }
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Command timed out: '{rule.Target}'" };
            }

            string stdout = stdoutTask.Result;
            string stderr = OperatingSystem.IsWindows() ? PowerShellStderrToText(stderrTask.Result) : stderrTask.Result;
            string output = string.IsNullOrEmpty(stdout)
                ? stderr
                : string.IsNullOrEmpty(stderr)
                    ? stdout
                    : $"{stdout.TrimEnd('\r', '\n')}\n{stderr}";

            if (!rule.HasContentCheck)
            {
                bool ok      = proc.ExitCode == 0;
                string value = Truncate(output.Trim().ReplaceLineEndings(" "), 80);
                return new RuleCheckResult { Status = ok ? CheckStatus.Passed : CheckStatus.Failed, Detail = $"Exit code {proc.ExitCode}  → \"{value}\"" };
            }

            // For content checks: non-zero exit code is only INVALID if:
            // Exit code is 127 (command not found)
            // Other exit codes (1, 2, etc.) mean the command ran but failed → evaluate output or fail
            if (proc.ExitCode == 127)
            {
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Command execution failed with exit code {proc.ExitCode}" };
            }

            var (matched, detail) = EvaluateContent(output, rule.ContentConditions, label: $"`{rule.Target}`");
            return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Failed to run command '{rule.Target}': {ex.Message}" };
        }
    }

    // ── Registry ─────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckRegistry(ParsedRule rule)
    {
        if (!OperatingSystem.IsWindows())
            return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = "Registry checks are only supported on Windows — skipped on this platform" };

        try
        {
            string keyPath = rule.Target;

            int firstBackslash = keyPath.IndexOf('\\');
            if (firstBackslash < 0)
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Invalid registry key path: {keyPath}" };

            string hiveName = keyPath[..firstBackslash].ToUpperInvariant();
            string subKey   = keyPath[(firstBackslash + 1)..];

            // Support both full names and common short aliases
            Microsoft.Win32.RegistryKey? hive = hiveName switch
            {
                "HKEY_LOCAL_MACHINE"  or "HKLM" => Microsoft.Win32.Registry.LocalMachine,
                "HKEY_CURRENT_USER"   or "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                "HKEY_CLASSES_ROOT"   or "HKCR" => Microsoft.Win32.Registry.ClassesRoot,
                "HKEY_USERS"          or "HKU"  => Microsoft.Win32.Registry.Users,
                "HKEY_CURRENT_CONFIG" or "HKCC" => Microsoft.Win32.Registry.CurrentConfig,
                _ => null
            };

            if (hive is null)
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Unknown registry hive: '{hiveName}' — valid hives: HKLM, HKCU, HKCR, HKU, HKCC" };

            using Microsoft.Win32.RegistryKey? key = hive.OpenSubKey(subKey);
            if (key is null)
            {
                // A missing key is a normal "condition not met" (Failed), not an error (Invalid)
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Registry key not found: {keyPath}" };
            }

            // ── Key existence only ────────────────────────────────────────
            if (!rule.HasContentCheck)
            {
                int valueCount = key.ValueCount;
                return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Registry key exists: {keyPath}  ({valueCount} values)" };
            }

            // ── 3-part: KEY -> ValueName -> [DataPattern] ─────────────────
            if (rule.RegistryValueName is not null)
            {
                object? value = key.GetValue(rule.RegistryValueName);
                if (value is null)
                {
                    // A missing value is a normal "condition not met" (Failed), not an error (Invalid)
                    return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Registry value '{rule.RegistryValueName}' not found in '{keyPath}'" };
                }

                string valueStr = FormatRegistryValue(value);

                // Value exists, no data pattern required
                if (rule.ContentConditions.Count == 0)
                    return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Registry value '{rule.RegistryValueName}' = \"{valueStr}\" in '{keyPath}'" };

                // Match data pattern against the value string
                var (matched, detail) = EvaluateContent(valueStr, rule.ContentConditions,
                    label: $"'{rule.RegistryValueName}' in {keyPath}");
                return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
            }

            // ── Fallback: match content against all name=value pairs ──────
            System.Text.StringBuilder allValues = new();
            foreach (string name in key.GetValueNames())
                allValues.AppendLine($"{name}={FormatRegistryValue(key.GetValue(name))}");

            var (matched2, detail2) = EvaluateContent(allValues.ToString(), rule.ContentConditions, label: keyPath);
            return new RuleCheckResult { Status = matched2 ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail2 };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Registry error: {ex.Message}" };
        }
    }

    /// <summary>
    /// Renders a registry value as text for content matching. <c>REG_MULTI_SZ</c> arrives as
    /// <see cref="T:string[]"/> and is joined with newlines so every element can match on its
    /// own line; <c>REG_BINARY</c> (<see cref="T:byte[]"/>) becomes an uppercase hex string.
    /// The default <see cref="object.ToString"/> would only yield the type name
    /// ("System.String[]"), which no pattern can ever match.
    /// </summary>
    internal static string FormatRegistryValue(object? value) => value switch
    {
        null           => string.Empty,
        string[] items => string.Join(Environment.NewLine, items),
        byte[] bytes   => Convert.ToHexString(bytes),
        _              => value.ToString() ?? string.Empty
    };

    // =========================================================================
    // Content evaluation  (shared by File, Directory, Command, Registry)
    // =========================================================================

    /// <summary>
    /// Evaluates one or more content conditions against <paramref name="content"/>.
    ///
    /// Single condition  → line-by-line: pass if ANY line satisfies the condition
    ///                     (or, for negated, if NO line matches the pattern).
    ///
    /// Multiple (&&) conditions → line-by-line: pass if ANY line simultaneously
    ///                            satisfies ALL conditions (Wazuh semantics).
    /// </summary>
    private static (bool matched, string detail) EvaluateContent(
        string content,
        List<ContentCondition> conditions,
        string label)
    {
        if (conditions.Count == 0)
            return (true, "No content conditions");

        if (conditions.Count == 1)
            return EvaluateSingleCondition(content, conditions[0], label);

        // Multi-condition (&&): look for a line that satisfies ALL conditions
        string[] lines = SplitLines(content);
        foreach (string line in lines)
        {
            if (conditions.All(c => LineMatchesCondition(line, c)))
                return (true, $"Matched line in {label}: \"{Truncate(line.Trim(), 80)}\"");
        }

        // Show the first non-empty line as context for the failure
        string sample = lines.FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "(empty)";
        return (false, $"No single line in {label} satisfies all {conditions.Count} AND-conditions  (first line: \"{Truncate(sample, 60)}\")");
    }

    private static (bool, string) EvaluateSingleCondition(
        string content, ContentCondition cond, string label)
    {
        if (cond.Operator == ContentOperator.Numeric)
            return EvaluateNumeric(content, cond, label);

        string[] lines = SplitLines(content);

        if (!cond.Negated)
        {
            // Pass if ANY line matches the pattern
            foreach (string line in lines)
            {
                if (MatchesPattern(line, cond.Pattern, cond.Operator))
                    return (true, $"Matched line in {label}: \"{Truncate(line.Trim(), 80)}\"");
            }
            // Show the first line as context so the user knows what was actually there
            string sample = lines.FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "(empty)";
            return (false, $"Pattern `{cond.Pattern}` not found in {label}  (first line: \"{Truncate(sample, 60)}\")");
        }
        else
        {
            // Pass if NO line matches the pattern
            foreach (string line in lines)
            {
                if (MatchesPattern(line, cond.Pattern, cond.Operator))
                    return (false, $"Forbidden pattern found in {label}: \"{Truncate(line.Trim(), 80)}\"");
            }
            // Show first line to confirm what IS in the content
            string sample = lines.FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "(empty)";
            return (true, $"Pattern `{cond.Pattern}` absent from {label}  (actual first line: \"{Truncate(sample, 60)}\")");
        }
    }

    private static (bool, string) EvaluateNumeric(
        string content, ContentCondition cond, string label)
    {
        Regex regex;
        try   { regex = new Regex(cond.Pattern, RegexOptions.Multiline); }
        catch { return (false, $"Invalid numeric regex pattern: `{cond.Pattern}`"); }

        Match match = regex.Match(content);
        if (!match.Success || match.Groups.Count < 2)
        {
            string sample = content.Trim().ReplaceLineEndings(" ");
            return (false, $"Pattern `{cond.Pattern}` found no capture group in {label}  (actual: \"{sample}\")");
        }

        if (!double.TryParse(match.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
            return (false, $"Captured '{match.Groups[1].Value}' in {label} is not numeric");

        (bool met, string sym) = cond.NumericOp switch
        {
            NumericComparison.LessThan           => (value < cond.NumericValue,  "<"),
            NumericComparison.LessThanOrEqual    => (value <= cond.NumericValue, "<="),
            NumericComparison.Equal              => (value == cond.NumericValue, "=="),
            NumericComparison.NotEqual           => (value != cond.NumericValue, "!="),
            NumericComparison.GreaterThanOrEqual => (value >= cond.NumericValue, ">="),
            NumericComparison.GreaterThan        => (value > cond.NumericValue,  ">"),
            _                                    => (false,                      "?")
        };

        bool finalPassed = cond.Negated ? !met : met;
        string valStr = value.ToString(CultureInfo.InvariantCulture);
        string numValStr = cond.NumericValue?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        return (finalPassed, $"Captured value = {valStr}  ({valStr} {sym} {numValStr} → {(finalPassed ? "PASS" : "FAIL")})  from {label}");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static bool MatchesPattern(string line, string pattern, ContentOperator op) =>
        op switch
        {
            ContentOperator.Literal => line.Contains(pattern, StringComparison.Ordinal),
            ContentOperator.Regex   => Regex.IsMatch(line, pattern),
            _                       => false
        };

    private static bool LineMatchesCondition(string line, ContentCondition cond)
    {
        bool raw = MatchesPattern(line, cond.Pattern, cond.Operator);
        return cond.Negated ? !raw : raw;
    }

    private static string[] SplitLines(string text) =>
        text.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries);

    private static string Truncate(string s, int max) => StringUtils.Truncate(s, max);

    private static string FormatBytes(long bytes) =>
        bytes switch
        {
            < 1024             => $"{bytes} B",
            < 1024 * 1024      => $"{bytes / 1024.0:F1} KB",
            _                  => $"{bytes / (1024.0 * 1024):F1} MB"
        };

    /// <summary>
    /// With -EncodedCommand, PowerShell writes errors and progress to stderr as CLIXML ("#&lt; CLIXML ...").
    /// Returns the error/warning text from it, or "" when it only held progress. Other text is returned as is.
    /// </summary>
    internal static string PowerShellStderrToText(string stderr)
    {
        const string header = "#< CLIXML";
        if (!stderr.Contains(header, StringComparison.Ordinal)) return stderr;

        try
        {
            string payload = Regex.Replace(stderr, "(?m)^#< CLIXML\r?\n", string.Empty);
            if (payload == stderr) return stderr;

            var root = XElement.Parse($"<root>{payload}</root>");
            if (!root.Elements().Any() || root.Elements().Any(element => element.Name.LocalName != "Objs"))
                return stderr;

            StringBuilder text = new();
            foreach (XNode node in root.Nodes())
            {
                if (node is XText plainText)
                {
                    text.Append(plainText.Value);
                    continue;
                }

                if (node is not XElement records) continue;
                foreach (XElement record in records.Elements())
                {
                    if (record.Name.LocalName != "S") continue;
                    string? stream = (string?)record.Attribute("S");
                    if (string.Equals(stream, "Error", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(stream, "Warning", StringComparison.OrdinalIgnoreCase))
                    {
                        string message = Regex.Replace(record.Value, "_x([0-9A-Fa-f]{4})_",
                            match => ((char)Convert.ToInt32(match.Groups[1].Value, 16)).ToString());
                        text.AppendLine(message.TrimEnd('\r', '\n'));
                    }
                }
            }

            return text.ToString().Trim();
        }
        catch (System.Xml.XmlException)
        {
            return stderr;
        }
    }
}
