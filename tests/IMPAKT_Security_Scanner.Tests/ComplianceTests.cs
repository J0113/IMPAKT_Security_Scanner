using System.Globalization;
using Compliance_Scanner;

namespace IMPAKT_Security_Scanner.Tests;

public class ComplianceTests
{
    [Fact]
    public void ScannerEvaluatesFileContent()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "compliance-enabled=yes\n");
            var check = new Check { Id = 1, Condition = "all", Rules = [$"f:{path} -> r:^compliance-enabled=yes$"] };
            Assert.Equal(CheckStatus.Passed, RuleChecker.EvaluateCheck(check, null).Status);
            File.WriteAllText(path, "compliance-enabled=no\n");
            Assert.Equal(CheckStatus.Failed, RuleChecker.EvaluateCheck(check, null).Status);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void MissingFileWithContentCheckFailsInsteadOfBeingInvalid()
    {
        string missing = Path.Combine(Path.GetTempPath(), "impakt-missing-" + Guid.NewGuid().ToString("N"));

        var positive = RuleChecker.EvaluateCheck(
            new Check { Id = 1, Condition = "all", Rules = [$"f:{missing} -> r:abc"] }, null);
        Assert.Equal(CheckStatus.Failed, positive.Status);
        Assert.False(positive.RuleResults[0].Invalid);

        var negated = RuleChecker.EvaluateCheck(
            new Check { Id = 2, Condition = "all", Rules = [$"not f:{missing} -> r:abc"] }, null);
        Assert.Equal(CheckStatus.Passed, negated.Status);
    }

    [Fact]
    public void MissingRegistryValueFailsInsteadOfBeingInvalid()
    {
        if (!OperatingSystem.IsWindows()) return;
        const string key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        string value = "impakt-missing-" + Guid.NewGuid().ToString("N");
        string rule = $"r:{key} -> {value} -> 1";

        var positive = RuleChecker.EvaluateCheck(
            new Check { Id = 1, Condition = "all", Rules = [rule] }, null);
        Assert.Equal(CheckStatus.Failed, positive.Status);
        Assert.False(positive.RuleResults[0].Invalid);

        var negated = RuleChecker.EvaluateCheck(
            new Check { Id = 2, Condition = "all", Rules = [$"not {rule}"] }, null);
        Assert.Equal(CheckStatus.Passed, negated.Status);
    }

    [Fact]
    public void PowerShellProgressClixmlIsDroppedFromStderr()
    {
        const string progressOnly = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">" +
            "<Obj S=\"progress\" RefId=\"0\"><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV></PR></MS></Obj></Objs>";

        Assert.Equal("", RuleChecker.PowerShellStderrToText(progressOnly));
    }

    [Fact]
    public void PowerShellErrorClixmlBecomesReadableText()
    {
        const string error = "native stderr\r\n#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">" +
            "<S S=\"Error\">Get-Item : Cannot find path 'C:\\x' because it does not exist._x000D__x000A_</S>" +
            "<S S=\"Warning\">Example warning</S><S S=\"error\">At line:1 char:1_x000D__x000A_</S></Objs>";

        string text = RuleChecker.PowerShellStderrToText(error);

        Assert.Contains("Cannot find path 'C:\\x' because it does not exist.", text);
        Assert.StartsWith("native stderr", text);
        Assert.Contains($"Example warning{Environment.NewLine}At line:1 char:1", text);
        Assert.DoesNotContain("CLIXML", text);
        Assert.Equal("plain stderr", RuleChecker.PowerShellStderrToText("plain stderr"));
    }

    [Fact]
    public void PowerShellErrorsAreReadableInCommandRulesOnWindows()
    {
        if (!OperatingSystem.IsWindows()) return;

        var check = new Check { Id = 1, Condition = "all", Rules = ["c:Write-Error 'impakt-clixml-probe' -> r:impakt-clixml-probe$"] };

        Assert.Equal(CheckStatus.Passed, RuleChecker.EvaluateCheck(check, null).Status);
    }

    [Fact]
    public void PolicyReadsNameOfRequirementsAndChecks()
    {
        const string yaml = """
            policy: { id: "p", file: "p.yml", name: "P", description: "d" }
            requirements:
              name: "Needs Windows"
              condition: all
              rules: ["c:cmd /c ver -> r:Windows"]
            checks:
              - id: 1
                name: "Ensure the thing"
                condition: all
                rules: ["f:/etc/hosts"]
            """;
        var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
            .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        SCAPolicy policy = deserializer.Deserialize<SCAPolicy>(yaml);

        Assert.Equal("Needs Windows", policy.Requirements!.Name);
        Assert.Equal("Ensure the thing", policy.Checks[0].Name);
    }

    [Fact]
    public void OnlyChecksWithoutTitleOrNameAreReported()
    {
        const string yaml = """
            policy: { id: "p", file: "p.yml", name: "P", description: "d" }
            checks:
              - id: 1
                name: "Has a name"
                rules: ["f:/etc/hosts"]
              - id: 2
                title: "Has a title"
                rules: ["f:/etc/hosts"]
              - id: 3
                rules: ["f:/etc/hosts"]
            """;
        var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
            .WithNamingConvention(YamlDotNet.Serialization.NamingConventions.UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        SCAPolicy policy = deserializer.Deserialize<SCAPolicy>(yaml);

        Assert.Equal([3], policy.CheckIdsWithoutDisplayTitle());
    }

    [Fact]
    public void GeneratedScannerConfigContainsOnlyComplianceSettings()
    {
        string path = Path.GetTempFileName();
        try
        {
            ScannerConfig.WriteTemplate(path);
            string contents = File.ReadAllText(path).ToLowerInvariant();
            Assert.DoesNotContain("sftp", contents);
            Assert.Contains("output_level", contents);
            Assert.Contains("report_file", contents);
            Assert.Contains("log_file", contents);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void NumericComparisonWorksUnderDutchCommaLocale()
    {
        CultureInfo previousCulture = Thread.CurrentThread.CurrentCulture;
        string path = Path.GetTempFileName();
        try
        {
            Thread.CurrentThread.CurrentCulture = new CultureInfo("nl-NL");
            File.WriteAllText(path, "max_drift = 1.5\n");

            var passingCheck = new Check
            {
                Id = 1,
                Condition = "all",
                Rules = [$"f:{path} -> n:max_drift = (\\d+\\.\\d+) compare <= 2.0"]
            };
            CheckResult passResult = RuleChecker.EvaluateCheck(passingCheck, null);
            Assert.Equal(CheckStatus.Passed, passResult.Status);
            Assert.Contains("1.5 <= 2", passResult.RuleResults[0].Detail);

            var failingCheck = new Check
            {
                Id = 2,
                Condition = "all",
                Rules = [$"f:{path} -> n:max_drift = (\\d+\\.\\d+) compare <= 1.25"]
            };
            CheckResult failResult = RuleChecker.EvaluateCheck(failingCheck, null);
            Assert.Equal(CheckStatus.Failed, failResult.Status);
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = previousCulture;
            File.Delete(path);
        }
    }

    [Fact]
    public void CommandRuleHandlesEmbeddedDoubleQuotes()
    {
        var check = new Check
        {
            Id = 1,
            Condition = "all",
            Rules = ["c:echo \"quoted value\" -> r:^quoted value$"]
        };
        CheckResult result = RuleChecker.EvaluateCheck(check, null);
        Assert.True(result.Status == CheckStatus.Passed,
            string.Join(Environment.NewLine, result.RuleResults.Select(rule => rule.Detail)));
    }

    [Fact]
    public void CommandRuleMarksTimeoutAsInvalid()
    {
        int previousTimeout = RuleChecker.CommandTimeoutMilliseconds;
        try
        {
            RuleChecker.CommandTimeoutMilliseconds = 150;
            string sleepCmd = OperatingSystem.IsWindows() ? "Start-Sleep -Seconds 5" : "sleep 5";
            var check = new Check
            {
                Id = 1,
                Condition = "all",
                Rules = [$"c:{sleepCmd} -> r:done"]
            };
            CheckResult result = RuleChecker.EvaluateCheck(check, null);
            Assert.Equal(CheckStatus.Invalid, result.Status);
            Assert.True(result.RuleResults[0].Invalid);
            Assert.Contains("timed out", result.RuleResults[0].Detail, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            RuleChecker.CommandTimeoutMilliseconds = previousTimeout;
        }
    }
}
