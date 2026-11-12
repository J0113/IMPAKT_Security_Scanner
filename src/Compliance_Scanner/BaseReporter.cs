namespace Compliance_Scanner;

/// <summary>
/// Abstract base reporter. Contains all print logic; subclasses provide
/// Write/WriteLine implementations (with or without color).
/// </summary>
public abstract class BaseReporter : IReporter
{
    protected OutputLevel Level { get; }

    protected BaseReporter(OutputLevel level = OutputLevel.Standard)
    {
        Level = level;
    }

    protected abstract void Write(string text, ConsoleColor? color = null);
    protected abstract void WriteLine(string text = "", ConsoleColor? color = null);

    protected void WritePass(string text) => Write(text, ConsoleColor.Green);
    protected void WriteFail(string text) => Write(text, ConsoleColor.Red);
    protected void WriteInvalid(string text) => Write(text, ConsoleColor.DarkYellow);
    protected void WriteLabel(string text) => Write(text, ConsoleColor.DarkCyan);
    protected void WriteGray(string text) => Write(text, ConsoleColor.DarkGray);

    protected static string Truncate(string text, int maxLength) => StringUtils.Truncate(text, maxLength);

    // =========================================================================
    // UI Structure
    // =========================================================================

    public void PrintBanner()
    {
        WriteLine("╔═════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLine("║             Compliance_Scanner              ║", ConsoleColor.Cyan);
        WriteLine("╚═════════════════════════════════════════════╝", ConsoleColor.Cyan);
        WriteLine();
    }

    public void PrintHelp()
    {
        PrintBanner();
        WriteLine("USAGE:", ConsoleColor.White);
        WriteLine("  Compliance_Scanner [options] <path/to/policy.yaml>   Run all checks from a policy file");
        WriteLine("  Compliance_Scanner [options] <path/to/dir>           Scan all .yml/.yaml policies in a directory,");
        WriteLine("                                               skipping those whose requirements don't apply");
        WriteLine();
        WriteLine("OPTIONS:", ConsoleColor.White);
        WriteLine("  --display-details           Show full rule details in console output");
        WriteLine("  --no-details                Show only header and summary (no requirements or rules)");
        WriteLine("  --output-dir <dir>          Root for default files (default: REPORTS_DIR or ./results/)");
        WriteLine("  -l, --log <file>            Write detailed output to a log file");
        WriteLine("  --json, -r, --report <file>  Write scan results as JSON (default: hardening-<host>.json)");
        WriteLine();
        WriteLine("CONFIG FILE OPTIONS:", ConsoleColor.White);
        WriteLine("  -c, --config <path>         Load configuration from YAML file");
        WriteLine("  --write-config [path]       Generate a template config file (default: config.yml)");
        WriteLine("                              Use with path to write to custom location");
        WriteLine();
        WriteLine("  -h, --help                  Show this help message");
        WriteLine();
        WriteLine("NOTES:", ConsoleColor.White);
        WriteLine("  - Config file is optional. By default, app looks for 'config.yml' in working dir");
        WriteLine("  - CLI arguments always override config file values");
        WriteLine("  - Default reports are written to REPORTS_DIR when set, otherwise ./results/");
        WriteLine("  - Scan results are also written as JSON to stdout; diagnostic logging uses stderr");
        WriteLine();
        WriteLine("EXAMPLES:", ConsoleColor.White);
        WriteLine("  Compliance_Scanner Policies/sample_policy.yaml");
        WriteLine("  Compliance_Scanner --display-details Policies/sample_policy.yaml");
        WriteLine("  Compliance_Scanner --write-config");
        WriteLine("  Compliance_Scanner --config custom.yml --no-details --json report.json Policies/");
        WriteLine();
    }

    // =========================================================================
    // Policy Execution Context
    // =========================================================================

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    {
        PrintBanner();

        WriteLine($"  Policy   : {policy.Policy.Name}");
        WriteLine($"  ID       : {policy.Policy.Id}");
        WriteLine($"  Platform : {platform}");
        WriteLine($"  Checks   : {policy.Checks.Count}");

        if (!string.IsNullOrWhiteSpace(policy.Policy.Description))
            WriteLine($"  Desc     : {policy.Policy.Description}");

        WriteLine();
    }

    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult)
    {
        if (Level == OutputLevel.Compact) return;

        WriteLine("══ Requirements " + new string('═', 52), ConsoleColor.Cyan);
        WriteLine($"  {requirementsCheck.DisplayTitle}");
        if (!string.IsNullOrWhiteSpace(requirementsCheck.Description))
            WriteLine($"  {requirementsCheck.Description}");

        WriteLabel("  ┌─ What requirements will be checked:\n");
        List<ParsedRule> parsedReqRules = requirementsCheck.Rules
            .Select(rule => RuleParser.Parse(rule, variables))
            .ToList();
        for (int i = 0; i < parsedReqRules.Count; i++)
        {
            WriteLabel($"  │  [{i + 1}] ");
            WriteLine(RuleParser.Explain(parsedReqRules[i]));
            WriteGray($"  │       raw  : {requirementsCheck.Rules[i]}\n");
        }
        WriteLabel("  └─\n");

        WriteLabel("  ┌─ Requirement results:\n");
        for (int i = 0; i < requirementsResult.RuleResults.Count; i++)
        {
            RuleResult ruleResult = requirementsResult.RuleResults[i];
            WriteLabel($"  │  [{i + 1}] ");
            if (ruleResult.Passed) WritePass("PASS"); else WriteFail("FAIL");
            WriteLine($"  {ruleResult.Detail}");
        }
        WriteLabel("  └─\n\n");

        if (requirementsResult.Status != CheckStatus.Passed)
        {
            WriteFail("  ✗ Requirements NOT met — policy scan aborted.\n");
            WriteFail($"    {requirementsResult.Reason}\n");
        }
        else
        {
            WritePass("  ✓ Requirements met — proceeding with checks.\n");
            WriteLine();
        }
    }

    // =========================================================================
    // Check Execution
    // =========================================================================

    public void PrintCheckHeader(Check check)
    {
        if (Level != OutputLevel.Detailed) return;

        WriteLine(new string('─', 68));

        Write($"  [#{check.Id,-4}] ", ConsoleColor.DarkGray);
        WriteLine(check.DisplayTitle, ConsoleColor.Yellow);

        if (!string.IsNullOrWhiteSpace(check.Description))
            WriteLine($"           Description : {check.Description}");
        if (!string.IsNullOrWhiteSpace(check.Rationale))
            WriteLine($"           Rationale   : {check.Rationale}", ConsoleColor.DarkGray);
        if (!string.IsNullOrWhiteSpace(check.Remediation))
            WriteLine($"           Remediation : {check.Remediation}", ConsoleColor.DarkYellow);

        WriteLine($"           Condition   : {check.Condition.ToUpper()} rules must pass", ConsoleColor.DarkGray);
        WriteLine();
    }

    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables)
    {
        if (Level != OutputLevel.Detailed) return;

        WriteLabel("  ┌─ What this check validates:\n");
        for (int i = 0; i < parsedRules.Count; i++)
        {
            WriteLabel($"  │  [{i + 1}] ");
            WriteLine(RuleParser.Explain(parsedRules[i]));
            WriteGray($"  │       raw  : {check.Rules[i]}\n");
            if (variables?.HasVariables == true)
            {
                string expanded = check.Rules[i];
                bool hasVar = false;
                foreach (var (key, value) in variables.Values)
                    if (expanded.Contains(key)) { expanded = expanded.Replace(key, value); hasVar = true; }
                if (hasVar)
                    WriteGray($"  │       exp  : {expanded}\n");
            }
        }
        WriteLabel("  └─\n\n");
    }

    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults)
    {
        if (Level != OutputLevel.Detailed) return;

        WriteLabel("  ┌─ Executing:\n");
        for (int i = 0; i < ruleResults.Count; i++)
        {
            RuleResult ruleResult = ruleResults[i];
            WriteLabel($"  │  [{i + 1}] ");
            if (ruleResult.Invalid) WriteInvalid("INVALID");
            else if (ruleResult.Passed) WritePass("PASS");
            else WriteFail("FAIL");
            WriteLine($"  {ruleResult.Detail}");
        }
    }

    public void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed)
    {
        if (Level != OutputLevel.Detailed) return;

        Write("  └─ ");
        if (result.Status == CheckStatus.Passed)
        {
            WritePass("✓ PASSED");
            WriteLine($"  ({result.Reason})");
        }
        else if (result.Status == CheckStatus.Failed)
        {
            WriteFail("✗ FAILED");
            WriteLine($"  ({result.Reason})");
        }
        else if (result.Status == CheckStatus.Invalid)
        {
            WriteInvalid("⚠ INVALID");
            WriteLine($"  ({result.Reason})");
        }

        WriteLine();
    }

    // =========================================================================
    // Summary
    // =========================================================================

    public void PrintScanSummary(int passed, int failed, int invalid, List<ScanCheckResult> checkResults)
    {
        WriteLine(new string('═', 68));
        WriteLine("  SCAN SUMMARY");
        WriteLine(new string('═', 68));

        int total = passed + failed + invalid;
        int score = total > 0 ? (int)Math.Round(passed * 100.0 / total) : 0;

        WritePass($"  Passed  : {passed}\n");
        WriteFail($"  Failed  : {failed}\n");
        WriteLine($"  Invalid : {invalid}", ConsoleColor.DarkYellow);
        WriteLine($"  Total   : {total}");
        Write("  Score   : ");

        ConsoleColor scoreColor = score >= 75 ? ConsoleColor.Green
                                : score >= 50 ? ConsoleColor.Yellow
                                : ConsoleColor.Red;
        WriteLine($"{score}%", scoreColor);
        WriteLine();

        if (Level != OutputLevel.Compact)
        {
            WriteLine("  CHECK STATUS:");
            foreach (ScanCheckResult result in checkResults)
            {
                Write($"    [{result.Id,-4}] ", ConsoleColor.DarkGray);
                if (result.Status == CheckStatus.Passed)
                    WritePass("✓ PASS");
                else if (result.Status == CheckStatus.Failed)
                    WriteFail("✗ FAIL");
                else if (result.Status == CheckStatus.Invalid)
                    WriteInvalid("⚠ INVALID");
                WriteLine($"  {result.Title}");
            }
            WriteLine();
        }
    }

    // =========================================================================
    // Directory Scanning
    // =========================================================================

    public void PrintDiscoveryHeader(string directoryPath, int foundCount)
    {
        PrintBanner();

        WriteLine("  POLICY DISCOVERY");
        WriteLine($"  Directory : {Path.GetFullPath(directoryPath)}");
        WriteLine($"  Found     : {foundCount} policy file(s)");
        WriteLine();

        WriteLine("  Checking requirements...", ConsoleColor.DarkGray);
    }

    public void PrintRequirementCheckLine(string fileName, bool met, string? note)
    {
        if (met)
        {
            Write($"    ✓ {fileName,-40}", ConsoleColor.Green);
            WriteLine($"  [{note}]", ConsoleColor.DarkGray);
        }
        else
        {
            Write($"    ✗ {fileName,-40}", ConsoleColor.DarkGray);
            WriteLine($"  [{note}]", ConsoleColor.DarkGray);
        }
    }

    public void PrintApplicablePoliciesLine(int applicableCount)
    {
        WriteLine();
        WriteLine($"  Running {applicableCount} applicable policy file(s)...");
        WriteLine();
    }

    public void PrintPolicyExecutionHeader(int index, int total, string policyFileName)
    {
        WriteLine($"{'═',-3} [{index}/{total}] {policyFileName} " +
                  new string('═', Math.Max(0, 52 - policyFileName.Length)),
                  ConsoleColor.Cyan);
        WriteLine();
    }

    public void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies)
    {
        WriteLine();
    }

    // =========================================================================
    // Error Messages
    // =========================================================================

    public void PrintError(string message)
    {
        WriteFail($"Error: {message}\n");
    }

    public void PrintWarning(string message)
    {
        WriteLine($"Warning: {message}", ConsoleColor.Yellow);
    }

    public void PrintInfo(string message)
    {
        WriteLine($"Info: {message}", ConsoleColor.Cyan);
    }

    public void PrintNoPolicesFound(string directoryPath)
    {
        WriteFail($"  No .yml / .yaml files found in {directoryPath}\n");
    }
}
