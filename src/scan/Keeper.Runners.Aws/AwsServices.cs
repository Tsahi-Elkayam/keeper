using System.Text.RegularExpressions;

namespace Keeper.Runners.Aws;

/// <summary>How a service is called: query (form POST, XML answer), json (X-Amz-Target), rest-json or rest-xml.</summary>
public sealed record AwsService(string Id, string Api, string? Version = null, string? Target = null, string JsonVersion = "1.1", bool Global = false,
    string? SigningName = null, string? Host = null)
{
    /// <summary>The name in the signature's scope (CloudWatch's API is "monitoring").</summary>
    public string Signing => SigningName ?? Id;
}

/// <summary>
/// The services Keeper knows how to call, and the actions it may: only those that read. An action must begin
/// with Describe, List, Get, Search, Lookup, BatchGet or Select, and must not be one that hands over a secret,
/// a credential or content (GetSecretValue, GetParameter, GetObject, GetPasswordData, GetAuthorizationToken...).
/// A REST API is called with GET, or with POST only where the service answers a POST as a read.
/// </summary>
public static partial class AwsServices
{
    public static readonly IReadOnlyDictionary<string, AwsService> Known = new[]
    {
        new AwsService("iam", "query", "2010-05-08", Global: true),
        new AwsService("sts", "query", "2011-06-15"),
        new AwsService("ec2", "query", "2016-11-15"),
        new AwsService("rds", "query", "2014-10-31"),
        new AwsService("elasticloadbalancing", "query", "2015-12-01"),
        new AwsService("autoscaling", "query", "2011-01-01"),
        new AwsService("cloudformation", "query", "2010-05-15"),
        new AwsService("sns", "query", "2010-03-31"),
        new AwsService("monitoring", "query", "2010-08-01"),
        new AwsService("redshift", "query", "2012-12-01"),
        new AwsService("elasticache", "query", "2015-02-02"),
        new AwsService("kms", "json", Target: "TrentService"),
        new AwsService("cloudtrail", "json", Target: "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"),
        new AwsService("config", "json", Target: "StarlingDoveService"),
        new AwsService("ssm", "json", Target: "AmazonSSM"),
        new AwsService("ecr", "json", Target: "AmazonEC2ContainerRegistry_V20150921"),
        new AwsService("ecs", "json", Target: "AmazonEC2ContainerServiceV20141113"),
        new AwsService("dynamodb", "json", Target: "DynamoDB_20120810", JsonVersion: "1.0"),
        new AwsService("acm", "json", Target: "CertificateManager"),
        new AwsService("secretsmanager", "json", Target: "secretsmanager"),
        new AwsService("logs", "json", Target: "Logs_20140328"),
        new AwsService("codebuild", "json", Target: "CodeBuild_20161006"),
        new AwsService("wafv2", "json", Target: "AWSWAF_20190729"),
        new AwsService("organizations", "json", Target: "AWSOrganizationsV20161128", Global: true),
        new AwsService("sso", "json", Target: "SWBExternalService", SigningName: "sso", Host: "sso"),
        new AwsService("identitystore", "json", Target: "AWSIdentityStore", JsonVersion: "1.1"),
        new AwsService("ce", "json", Target: "AWSInsightsIndexService", Global: true),
        new AwsService("lambda", "rest-json"),
        new AwsService("eks", "rest-json"),
        new AwsService("backup", "rest-json"),
        new AwsService("guardduty", "rest-json"),
        new AwsService("securityhub", "rest-json"),
        new AwsService("inspector2", "rest-json"),
        new AwsService("access-analyzer", "rest-json", SigningName: "access-analyzer"),
        new AwsService("s3", "rest-xml"),
        new AwsService("route53", "rest-xml", Global: true),
        new AwsService("cloudfront", "rest-xml", Global: true),
    }.ToDictionary(s => s.Id, StringComparer.Ordinal);

    /// <summary>Services whose every call is billed (Cost Explorer: a cent each): read at most daily.</summary>
    public static readonly IReadOnlySet<string> Billed = new HashSet<string>(StringComparer.Ordinal) { "ce" };

    // Reads that hand over what Keeper must never hold: secret values, credentials and tokens, content.
    private static readonly HashSet<string> Denied = new(StringComparer.Ordinal)
    {
        "GetSecretValue", "BatchGetSecretValue", "GetRandomPassword",
        "GetParameter", "GetParameters", "GetParametersByPath", "GetParameterHistory",
        "GetObject", "GetObjectTorrent", "SelectObjectContent",
        "GetPasswordData", "GetConsoleOutput", "GetConsoleScreenshot", "GetLaunchTemplateData",
        "GetAuthorizationToken", "GetFederationToken", "GetSessionToken", "GetAccessKeyInfo",
        "GetCredentialsForIdentity", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity", "GetId",
        "GetRoleCredentials", "GetDataKey", "GetCallerIdentityToken", "GetSigninToken",
        "GetQueryResults", "GetLogEvents", "GetLogRecord", "FilterLogEvents", "GetItem", "BatchGetItem",
        "GetFunction", "GetLayerVersion", "GetLayerVersionByArn", "GetTemplate", "GetGeneratedTemplate", "GetDeploymentTarget",
        "GetClusterCredentials", "GetClusterCredentialsWithIAM", "GetDownloadUrlForLayer", "BatchGetImage",
        "GetCommandInvocation", "ListCommandInvocations", "ListCommands", "GetAutomationExecution", "DescribeAutomationExecutions",
        // Their parameters carry the commands' own text, secrets included.
        "GetMaintenanceWindowTask", "DescribeMaintenanceWindowTasks", "GetMaintenanceWindowExecutionTaskInvocation", "DescribeAssociation",
    };

    [GeneratedRegex(@"\A(Describe|List|Get|Search|Lookup|BatchGet|Select)[A-Z][A-Za-z0-9]{0,99}\z", RegexOptions.CultureInvariant)]
    private static partial Regex ReadAction();

    [GeneratedRegex(@"\A[a-z][a-z0-9-]{1,40}\z", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceId();

    [GeneratedRegex(@"\A[a-z]{2}(-[a-z]+)+-[0-9]{1,2}\z", RegexOptions.CultureInvariant)]
    private static partial Regex RegionId();

    /// <summary>Why the action may not be called, or null.</summary>
    public static string? ActionProblem(string? action)
    {
        if (action is null || !ReadAction().IsMatch(action))
            return "action must be a read: Describe..., List..., Get..., Search..., Lookup..., BatchGet... or Select...";
        return Denied.Contains(action)
            ? $"{action} hands over a secret, a credential or content; Keeper never calls it"
            : null;
    }

    public static bool IsServiceId(string? id) => id is not null && ServiceId().IsMatch(id);

    public static bool IsRegion(string? id) => id is not null && RegionId().IsMatch(id);

    /// <summary>A REST operation Keeper may call: its method and path ('*' one segment).</summary>
    public sealed record RestOperation(string Method, string Path);

    // Declared before Rest, which reads it: static fields are set in the order they are written.
    private static readonly string[] S3Settings =
    [
        "GetBucketAcl", "GetBucketPolicy", "GetBucketPolicyStatus", "GetBucketEncryption", "GetBucketVersioning", "GetBucketLogging",
        "GetPublicAccessBlock", "GetBucketOwnershipControls", "GetBucketLifecycleConfiguration", "GetBucketReplication", "GetBucketTagging",
        "GetBucketLocation", "GetBucketWebsite", "GetBucketCors", "GetBucketNotificationConfiguration", "GetObjectLockConfiguration",
    ];

    /// <summary>
    /// The REST operations Keeper may call, by service and action. A REST API names its operation by its path,
    /// not by the action a rule writes, so the two are tied here: a rule's action must be one of these, and its
    /// path (filled in) must be that action's path. Anything else is refused - GetFunction, which hands over a
    /// download link to the code, is not here.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, RestOperation>> Rest =
        new Dictionary<string, IReadOnlyDictionary<string, RestOperation>>(StringComparer.Ordinal)
        {
            ["lambda"] = Ops(
                ("ListFunctions", "get", "/2015-03-31/functions/"),
                ("GetFunctionConfiguration", "get", "/2015-03-31/functions/*/configuration"),
                ("GetPolicy", "get", "/2015-03-31/functions/*/policy"),
                ("GetFunctionUrlConfig", "get", "/2021-10-31/functions/*/url"),
                ("ListFunctionUrlConfigs", "get", "/2021-10-31/functions/*/urls"),
                ("ListEventSourceMappings", "get", "/2015-03-31/event-source-mappings/"),
                ("ListLayers", "get", "/2018-10-31/layers")),
            ["eks"] = Ops(
                ("ListClusters", "get", "/clusters"),
                ("DescribeCluster", "get", "/clusters/*"),
                ("ListNodegroups", "get", "/clusters/*/node-groups"),
                ("DescribeNodegroup", "get", "/clusters/*/node-groups/*"),
                ("ListAccessEntries", "get", "/clusters/*/access-entries")),
            ["backup"] = Ops(
                ("ListBackupVaults", "get", "/backup-vaults/"),
                ("DescribeBackupVault", "get", "/backup-vaults/*"),
                ("GetBackupVaultAccessPolicy", "get", "/backup-vaults/*/access-policy"),
                ("ListRecoveryPointsByBackupVault", "get", "/backup-vaults/*/recovery-points/"),
                ("ListBackupPlans", "get", "/backup/plans/"),
                ("GetBackupPlan", "get", "/backup/plans/*/"),
                ("ListBackupSelections", "get", "/backup/plans/*/selections/"),
                ("ListProtectedResources", "get", "/resources/"),
                ("ListBackupJobs", "get", "/backup-jobs/")),
            ["guardduty"] = Ops(
                ("ListDetectors", "get", "/detector"),
                ("GetDetector", "get", "/detector/*"),
                ("ListFindings", "post", "/detector/*/findings"),
                ("GetFindings", "post", "/detector/*/findings/get"),
                ("GetFindingsStatistics", "post", "/detector/*/findings/statistics")),
            ["securityhub"] = Ops(
                ("DescribeHub", "get", "/accounts"),
                ("GetFindings", "post", "/findings"),
                ("GetEnabledStandards", "post", "/standards/get"),
                ("BatchGetSecurityControls", "post", "/securityControls/batchGet")),
            ["inspector2"] = Ops(
                ("ListFindings", "post", "/findings/list"),
                ("ListCoverage", "post", "/coverage/list"),
                ("ListFindingAggregations", "post", "/findings/aggregation/list"),
                ("BatchGetAccountStatus", "post", "/status/batch/get")),
            ["access-analyzer"] = Ops(
                ("ListAnalyzers", "get", "/analyzer"),
                ("ListFindings", "post", "/finding"),
                ("ListFindingsV2", "post", "/findingv2"),
                ("GetFindingsStatistics", "post", "/analyzer/findings/statistics")),
            ["route53"] = Ops(
                ("ListHostedZones", "get", "/2013-04-01/hostedzone"),
                ("GetHostedZone", "get", "/2013-04-01/hostedzone/*"),
                ("ListResourceRecordSets", "get", "/2013-04-01/hostedzone/*/rrset"),
                ("GetDNSSEC", "get", "/2013-04-01/hostedzone/*/dnssec"),
                ("ListQueryLoggingConfigs", "get", "/2013-04-01/queryloggingconfig")),
            ["cloudfront"] = Ops(
                ("ListDistributions", "get", "/2020-05-31/distribution"),
                ("GetDistributionConfig", "get", "/2020-05-31/distribution/*/config")),
            // S3: the bucket list, and one bucket's settings (by subresource, checked apart) - never an object.
            ["s3"] = Ops([("ListBuckets", "get", "/"), .. S3Settings.Select(a => (a, "get", "/*"))]),
        };

    private static IReadOnlyDictionary<string, RestOperation> Ops(params (string Action, string Method, string Path)[] operations) =>
        operations.ToDictionary(o => o.Action, o => new RestOperation(o.Method, o.Path), StringComparer.Ordinal);

    /// <summary>
    /// Whether a path (its {placeholders} standing for one segment each) is the operation's path. A segment is
    /// plain characters, or the escaped colon of an ARN (%3A) - never another escape, which could hide a / or a
    /// .. that the URI would act on, and never only dots.
    /// </summary>
    public static bool IsPath(RestOperation operation, string path)
    {
        var bare = System.Text.RegularExpressions.Regex.Replace(path, @"\{[A-Za-z_][A-Za-z0-9_.]{0,63}\}", "x");
        if (bare.Split('/').Any(segment => segment.Length > 0 && segment.Trim('.').Length == 0))
            return false;
        return System.Text.RegularExpressions.Regex.IsMatch(bare, @"\A" + System.Text.RegularExpressions.Regex.Escape(operation.Path)
            .Replace(@"\*", "(?:[A-Za-z0-9_.-]|%3A)+", StringComparison.Ordinal) + @"\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// The host for a service in a region - always under amazonaws.com, never anything a rule or an answer
    /// names. Global services are one host, signed in the home region.
    /// </summary>
    public static string Host(AwsService service, string region) => service.Id switch
    {
        "iam" => "iam.amazonaws.com",
        "route53" => "route53.amazonaws.com",
        "cloudfront" => "cloudfront.amazonaws.com",
        "organizations" => "organizations.us-east-1.amazonaws.com",
        "ce" => "ce.us-east-1.amazonaws.com",
        "sso" => $"portal.sso.{region}.amazonaws.com",
        _ => $"{service.Id}.{region}.amazonaws.com",
    };

    /// <summary>The region a global service is signed in; regional ones are signed where they are called.</summary>
    public static string SigningRegion(AwsService service, string region) =>
        service.Id is "iam" or "route53" or "cloudfront" or "organizations" or "ce" ? "us-east-1" : region;
}
