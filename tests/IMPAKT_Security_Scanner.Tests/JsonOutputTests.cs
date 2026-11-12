using System.Diagnostics;
using System.Text.Json;
using Compliance_Scanner;

namespace IMPAKT_Security_Scanner.Tests;

public sealed class JsonOutputTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "impakt-json-" + Guid.NewGuid().ToString("N"));

    public JsonOutputTests() => Directory.CreateDirectory(directory);

    [Theory]
    [InlineData(true, 0, "passed")]
    [InlineData(false, 1, "failed")]
    public async Task ScanWritesJsonReportAndTextLog(bool passes, int exitCode, string status)
    {
        string evidence = Path.Combine(directory, "evidence.txt");
        File.WriteAllText(evidence, passes ? "enabled=yes\n" : "enabled=no\n");
        string policy = WritePolicy("policy.yaml", $"f:{evidence} -> r:^enabled=yes$");
        var run = await Run("--output-dir", "reports", policy);
        Assert.Equal(exitCode, run.ExitCode);
        using var json = JsonDocument.Parse(run.Output);
        Assert.Equal(exitCode, json.RootElement.GetProperty("exitCode").GetInt32());
        Assert.Equal("Compliance_Scanner", json.RootElement.GetProperty("scanner").GetString());
        var result = json.RootElement.GetProperty("policies")[0].GetProperty("checks")[0];
        Assert.Equal(status, result.GetProperty("status").GetString());
        Assert.Equal(passes, result.GetProperty("rules")[0].GetProperty("passed").GetBoolean());
        Assert.Equal("Enable configuration", result.GetProperty("remediation").GetString());
        Assert.Equal(1, json.RootElement.GetProperty("summary").GetProperty("total").GetInt32());
        string[] files = Directory.GetFiles(Path.Combine(directory, "reports"));
        Assert.Equal(2, files.Length);
        Assert.Single(files, file => file.EndsWith(".log"));
        string report = Assert.Single(files, file => file.EndsWith(".json"));
        Assert.Equal(File.ReadAllText(report).Trim(), run.Output.Trim());
        Assert.Contains("JSON report:", run.Error);
    }

    [Fact]
    public async Task DirectoryScanRetainsEveryPolicyAndItsResults()
    {
        string policies = Path.Combine(directory, "policies");
        Directory.CreateDirectory(policies);
        string evidence = Path.Combine(directory, "exists.txt");
        File.WriteAllText(evidence, "present");
        WritePolicy("policies/one.yaml", $"f:{evidence}");
        WritePolicy("policies/two.yaml", $"f:{evidence}-missing");
        var run = await Run("--output-dir", "reports", policies);
        Assert.Equal(1, run.ExitCode);
        using var json = JsonDocument.Parse(run.Output);
        Assert.Equal(2, json.RootElement.GetProperty("policies").GetArrayLength());
        var summary = json.RootElement.GetProperty("summary");
        Assert.Equal(1, summary.GetProperty("passed").GetInt32());
        Assert.Equal(1, summary.GetProperty("failed").GetInt32());
    }

    [Fact]
    public async Task PolicyParseErrorsAreRecordedWithoutLosingOtherResults()
    {
        string policies = Path.Combine(directory, "policies");
        Directory.CreateDirectory(policies);
        string evidence = Path.Combine(directory, "exists.txt");
        File.WriteAllText(evidence, "present");
        WritePolicy("policies/good.yaml", $"f:{evidence}");
        File.WriteAllText(Path.Combine(policies, "broken.yaml"), "policy: [broken");
        var run = await Run("--output-dir", "reports", policies);
        Assert.Equal(1, run.ExitCode);
        using var json = JsonDocument.Parse(run.Output);
        Assert.Equal(1, json.RootElement.GetProperty("policies").GetArrayLength());
        Assert.Equal(1, json.RootElement.GetProperty("errors").GetArrayLength());
        var broken = json.RootElement.GetProperty("discovery").EnumerateArray()
            .Single(item => item.GetProperty("reason").GetString() == "parse error");
        Assert.False(broken.GetProperty("applicable").GetBoolean());
        Assert.False(string.IsNullOrWhiteSpace(broken.GetProperty("error").GetString()));
    }

    [Fact]
    public async Task MissingPolicyStillProducesAJsonErrorReport()
    {
        var run = await Run("--output-dir", "reports", "missing.yaml");
        Assert.Equal(1, run.ExitCode);
        using var json = JsonDocument.Parse(run.Output);
        var policy = json.RootElement.GetProperty("policies")[0];
        Assert.Equal("error", policy.GetProperty("status").GetString());
        Assert.Contains("not found", policy.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RequirementsFailureRemainsStructured()
    {
        string policy = WritePolicy("policy.yaml", "f:unused");
        File.AppendAllText(policy, "\nrequirements:\n  title: Unmet requirement\n  condition: all\n  rules:\n    - "
            + JsonSerializer.Serialize("f:" + Path.Combine(directory, "missing")) + "\n");
        var run = await Run("--output-dir", "reports", policy);
        Assert.Equal(1, run.ExitCode);
        using var json = JsonDocument.Parse(run.Output);
        var result = json.RootElement.GetProperty("policies")[0];
        Assert.Equal("requirementsNotMet", result.GetProperty("status").GetString());
        Assert.Equal("Unmet requirement", result.GetProperty("requirements").GetProperty("title").GetString());
        Assert.Equal("failed", result.GetProperty("requirements").GetProperty("status").GetString());
        Assert.Equal(0, result.GetProperty("checks").GetArrayLength());
    }

    [Fact]
    public async Task ReportAliasAndConfigBothWriteJsonWithCliPrecedence()
    {
        string policy = WritePolicy("policy.yaml", $"!f:{Path.Combine(directory, "missing")}");
        string config = Path.Combine(directory, "config.yml");
        File.WriteAllText(config, "report_file: config-report.json\n");
        var run = await Run("--config", config, "--report", "custom-report.json", policy);
        Assert.Equal(0, run.ExitCode);
        using var json = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "custom-report.json")));
        Assert.Equal("1.0", json.RootElement.GetProperty("schemaVersion").GetString());
        Assert.False(File.Exists(Path.Combine(directory, "config-report.json")));
    }

    [Fact]
    public async Task UnknownOptionIsRejected()
    {
        var run = await Run("--unknown-flag", "value", "policy.yaml");
        Assert.Equal(1, run.ExitCode);
        Assert.Contains("unknown option", run.Error);
    }

    [Fact]
    public async Task CommandRulesDoNotWaitForScannerStandardInput()
    {
        string command = OperatingSystem.IsWindows()
            ? "[Console]::In.ReadToEnd(); echo \"quoted value\""
            : "cat >/dev/null; echo \"quoted value\"";
        string policy = WritePolicy("command.yaml", $"c:{command} -> r:^quoted value$");

        // Run keeps the scanner's input pipe open, as a CI test host can do.
        var run = await Run("--output-dir", "reports", policy);

        Assert.True(run.ExitCode == 0, $"Scanner failed: {run.Output}\n{run.Error}");
        using var json = JsonDocument.Parse(run.Output);
        var check = json.RootElement.GetProperty("policies")[0].GetProperty("checks")[0];
        Assert.Equal("passed", check.GetProperty("status").GetString());
    }

    [Fact]
    public void UnknownYamlConfigFieldIsRejected()
    {
        string path = Path.Combine(directory, "invalid.yml");
        File.WriteAllText(path, "unknown_field: value\n");
        Assert.Throws<InvalidOperationException>(() => ScannerConfig.LoadFromFile(path));
    }

    private string WritePolicy(string name, string rule)
    {
        string path = Path.Combine(directory, name);
        File.WriteAllText(path, """
            policy:
              id: json-test
              name: JSON test
            checks:
              - id: 1
                title: Expected configuration
                description: Validate file evidence
                remediation: Enable configuration
                condition: all
                rules:
            """ + "\n      - " + JsonSerializer.Serialize(rule) + "\n");
        return path;
    }

    private async Task<(int ExitCode, string Output, string Error)> Run(params string[] arguments)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            WorkingDirectory = directory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(typeof(RuleChecker).Assembly.Location);
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        start.Environment.Remove("REPORTS_DIR");
        using var process = Process.Start(start)!;
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            throw;
        }
        return (process.ExitCode, await stdout, await stderr);
    }

    public void Dispose() => Directory.Delete(directory, recursive: true);
}
