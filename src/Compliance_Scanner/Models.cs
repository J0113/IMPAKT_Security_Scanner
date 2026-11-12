namespace Compliance_Scanner;

using YamlDotNet.Serialization;

// ---------------------------------------------------------------------------
// Check status enumeration
// ---------------------------------------------------------------------------

/// <summary>Status of a check result: Passed, Failed, or Invalid (unexecutable).</summary>
public enum CheckStatus
{
    Passed,
    Failed,
    Invalid
}

// ---------------------------------------------------------------------------
// Console output verbosity level
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Check condition enumeration
// ---------------------------------------------------------------------------

/// <summary>Logic applied to the rule list when evaluating a check or requirements block.</summary>
public enum CheckCondition
{
    /// <summary>ALL rules must pass.</summary>
    All,
    /// <summary>At least one rule must pass.</summary>
    Any,
    /// <summary>No rules may pass (all must fail).</summary>
    None,
    /// <summary>Unrecognised condition string — check will be marked Invalid.</summary>
    Unknown
}

// ---------------------------------------------------------------------------
// Console output verbosity level
// ---------------------------------------------------------------------------

/// <summary>Controls how much detail the console reporter outputs.</summary>
public enum OutputLevel
{
    /// <summary>Only banner, policy header, and summary counts/score.</summary>
    Compact,
    /// <summary>Default: banner, policy header, requirements, per-check results, full summary.</summary>
    Standard,
    /// <summary>Everything: includes rule explanations and rule results per check.</summary>
    Detailed
}

// ---------------------------------------------------------------------------
// Policy variables for substitution (e.g., $hosts -> /etc/hosts)
// ---------------------------------------------------------------------------
public sealed class PolicyVariables
{
    /// <summary>
    /// Mapping of variable names (e.g., "$hosts") to their values (e.g., "/etc/hosts").
    /// Used for variable substitution in rule strings.
    /// </summary>
    public Dictionary<string, string> Values { get; set; } = new();

    /// <summary>
    /// Determines if this variables collection has any entries.
    /// </summary>
    public bool HasVariables => Values.Count > 0;
}

// ---------------------------------------------------------------------------
// Top-level policy file (YAML root)
// ---------------------------------------------------------------------------
public sealed class SCAPolicy
{
    public PolicyMetadata Policy    { get; set; } = new();
    public Requirements?  Requirements { get; set; }

    /// <summary>
    /// YAML-mapped variables (deserialized as Dictionary).
    /// Converted to PolicyVariables on access via Variables property.
    /// </summary>
    [YamlMember(Alias = "variables")]
    public Dictionary<string, string>? VariablesDict { get; set; }

    private PolicyVariables? _variables;

    /// <summary>
    /// Parsed and wrapped variables for use throughout the application.
    /// </summary>
    [YamlIgnore]
    public PolicyVariables? Variables
    {
        get
        {
            if (VariablesDict is null) return null;
            return _variables ??= new PolicyVariables { Values = VariablesDict };
        }
    }

    public List<Check>    Checks   { get; set; } = [];

    /// <summary>IDs of checks without a title or name.</summary>
    public List<int> CheckIdsWithoutDisplayTitle() =>
        Checks.Where(check => string.IsNullOrWhiteSpace(check.DisplayTitle)).Select(check => check.Id).ToList();
}

// ---------------------------------------------------------------------------
// policy: section
// ---------------------------------------------------------------------------
public sealed class PolicyMetadata
{
    public string       Id          { get; set; } = string.Empty;
    public string       File        { get; set; } = string.Empty;
    public string       Name        { get; set; } = string.Empty;
    public string       Description { get; set; } = string.Empty;
    public List<string>? References { get; set; }
}

// ---------------------------------------------------------------------------
// requirements: section  — must pass before any checks run
// ---------------------------------------------------------------------------
public sealed class Requirements
{
    public string       Title       { get; set; } = string.Empty;
    public string       Name        { get; set; } = string.Empty;
    public string       Description { get; set; } = string.Empty;
    /// <summary>YAML value: all | any | none</summary>
    public string       Condition   { get; set; } = "any";
    public List<string> Rules       { get; set; } = [];

    private CheckCondition? _conditionEnum;
    /// <summary>Parsed <see cref="CheckCondition"/> derived from the YAML <see cref="Condition"/> string.</summary>
    [YamlIgnore]
    public CheckCondition ConditionEnum =>
        _conditionEnum ??= Condition.ToLowerInvariant() switch
        {
            "all"  => CheckCondition.All,
            "any"  => CheckCondition.Any,
            "none" => CheckCondition.None,
            _      => CheckCondition.Unknown
        };
}

// ---------------------------------------------------------------------------
// checks: list item
// ---------------------------------------------------------------------------
public sealed class Check
{
    public int          Id          { get; set; }

    /// <summary>Check title as used by Wazuh 4.x policies (<c>title:</c>).</summary>
    public string       Title       { get; set; } = string.Empty;

    /// <summary>Check name as used by Wazuh 5.x policies (<c>name:</c>).</summary>
    [YamlMember(Alias = "name")]
    public string       Name        { get; set; } = string.Empty;

    /// <summary>Title used in reports: <see cref="Title"/> when set, otherwise <see cref="Name"/>.</summary>
    [YamlIgnore]
    public string       DisplayTitle => !string.IsNullOrWhiteSpace(Title) ? Title : Name;

    public string       Description { get; set; } = string.Empty;
    public string       Rationale   { get; set; } = string.Empty;
    public string       Remediation { get; set; } = string.Empty;
    /// <summary>YAML value: all | any | none</summary>
    public string       Condition   { get; set; } = "all";
    public List<string> Rules       { get; set; } = [];

    private CheckCondition? _conditionEnum;
    /// <summary>Parsed <see cref="CheckCondition"/> derived from the YAML <see cref="Condition"/> string.</summary>
    [YamlIgnore]
    public CheckCondition ConditionEnum =>
        _conditionEnum ??= Condition.ToLowerInvariant() switch
        {
            "all"  => CheckCondition.All,
            "any"  => CheckCondition.Any,
            "none" => CheckCondition.None,
            _      => CheckCondition.Unknown
        };
}

/// <summary>
/// Represents the result of executing a single check during a scan.
/// Used for reporting and summarization.
/// </summary>
public sealed class ScanCheckResult
{
    /// <summary>Check identifier.</summary>
    public required int Id { get; init; }

    /// <summary>Check title/name.</summary>
    public required string Title { get; init; }

    /// <summary>Status of the check result.</summary>
    public required CheckStatus Status { get; init; }

    /// <summary>Reason for the result (e.g., "Condition 'ALL': 19/19 rules passed").</summary>
    public required string Reason { get; init; }
}
