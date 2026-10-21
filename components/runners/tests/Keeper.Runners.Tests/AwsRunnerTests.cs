using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Runners.Aws;

namespace Keeper.Runners.Tests;

/// <summary>A stub AWS: answers by host and action; AWS's documentation key, never a real one.</summary>
internal sealed class FakeAws(Func<HttpRequestMessage, string, HttpResponseMessage> respond, IReadOnlyList<string>? accounts = null,
    IReadOnlyList<string>? regions = null, string? refusedAccount = null) : IConnection, IAwsConnection
{
    public List<(string Host, string Body, string Authorization, string? Target)> Sent { get; } = [];
    public string Instance => "aws-test";
    public string Type => "aws";
    public string Endpoint => "eu-central-1";
    public string AuthKind => "aws-access-key";
    public string? Identity => "AKIAIOSFODNN7EXAMPLE";
    public JsonObject Options { get; } = [];
    public IReadOnlyList<string> AwsAccounts => accounts ?? [];
    public IReadOnlyList<string> AwsRegions => regions ?? ["eu-central-1"];
    public string? Secret(string name) => null;
    public NetworkCredential? WindowsCredential() => null;
    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<AwsCredentials> AwsCredentialsAsync(string? account, CancellationToken cancellationToken) =>
        account is not null && account == refusedAccount
            ? throw new InvalidOperationException($"AccessDenied assuming the role in {account}")
            : Task.FromResult(new AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", account is null ? null : "token-" + account));

    public HttpMessageHandler CreateHttpHandler() => new StubHandler(request =>
    {
        var body = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult() ?? "";
        lock (Sent)
            Sent.Add((request.RequestUri!.Host, request.RequestUri.PathAndQuery + "|" + body, request.Headers.GetValues("Authorization").Single(),
                request.Headers.TryGetValues("X-Amz-Target", out var t) ? t.Single() : null));
        return respond(request, body);
    });

    public static HttpResponseMessage Xml(string xml, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(xml, Encoding.UTF8, "text/xml") };
}

public sealed class AwsRunnerTests
{
    private static Task<RunnerResult> Run(FakeAws aws, params (string, JsonNode?)[] fields) =>
        new AwsRunner().RunAsync(Context.Query("aws", "id", fields), Context.For(aws), CancellationToken.None);

    private static IEnumerable<string> Problems(params (string, JsonNode?)[] fields) => new AwsRunner().Validate(Context.Query("aws", "id", fields));

    [Theory]
    [InlineData("iam", "CreateUser")]
    [InlineData("iam", "DeleteUser")]
    [InlineData("s3", "PutBucketPolicy")]
    [InlineData("secretsmanager", "GetSecretValue")]       // a read, but of a secret
    [InlineData("ssm", "GetParameters")]
    [InlineData("ec2", "GetPasswordData")]
    [InlineData("ecr", "GetAuthorizationToken")]
    [InlineData("sts", "AssumeRole")]
    [InlineData("iam", "Describe")]                        // no noun: not an action
    public void Only_reads_that_hand_over_nothing_are_allowed(string service, string action)
    {
        Assert.NotEmpty(Problems(("service", service), ("action", action), ("items", "//member")));
    }

    [Fact]
    public void Only_services_keeper_knows_are_read_and_a_billed_one_says_so()
    {
        Assert.NotEmpty(Problems(("service", "glue"), ("action", "GetConnections")));                                       // not in the table
        Assert.NotEmpty(Problems(("service", "glue"), ("action", "GetConnections"), ("api", "json"), ("target", "AWSGlue")));   // a rule cannot add one
        Assert.NotEmpty(Problems(("service", "kms"), ("action", "ListKeys"), ("target", "SomethingElse")));                    // nor change one
        Assert.Contains(Problems(("service", "ce"), ("action", "GetCostAndUsage")), p => p.Contains("billed", StringComparison.Ordinal));
        Assert.Empty(Problems(("service", "ce"), ("action", "GetCostAndUsage"), ("billed", "daily")));
    }

    [Theory]
    [InlineData("Action")]
    [InlineData("version")]
    [InlineData("X-Amz-Security-Token")]
    public void No_param_names_the_request_itself(string name)
    {
        Assert.NotEmpty(Problems(("service", "iam"), ("action", "ListUsers"), ("items", "//member"), ("params", new JsonObject { [name] = "DeleteUser" })));
        Assert.NotEmpty(Problems(("service", "iam"), ("action", "ListUsers"), ("items", "//member"), ("next", new JsonObject { ["from"] = "//Marker", ["to"] = name })));
    }

    [Theory]
    [InlineData("ListFunctions", "/2015-03-31/functions/{FunctionName}")]       // GetFunction's path: the code's download link
    [InlineData("GetFunctionConfiguration", "/2015-03-31/functions/{FunctionName}")]
    [InlineData("GetFunction", "/2015-03-31/functions/{FunctionName}")]           // not a read Keeper makes
    public void A_rest_action_is_read_at_its_own_path_only(string action, string path)
    {
        Assert.NotEmpty(Problems(("service", "lambda"), ("action", action), ("path", path)));
        Assert.Empty(Problems(("service", "lambda"), ("action", "GetFunctionConfiguration"), ("path", "/2015-03-31/functions/{FunctionName}/configuration")));
    }

    [Fact]
    public void An_aws_for_each_lists_its_objects_with_an_action_and_fills_top_level_params_only()
    {
        Assert.NotEmpty(Problems(("service", "iam"), ("action", "ListAttachedUserPolicies"), ("items", "//member"), ("params", new JsonObject { ["UserName"] = "{UserName}" }),
            ("for_each", new JsonObject { ["values"] = new JsonArray("alice"), ["field"] = "UserName" })));
        Assert.NotEmpty(Problems(("service", "securityhub"), ("action", "GetFindings"), ("path", "/findings"), ("method", "post"),
            ("params", new JsonObject { ["Filters"] = new JsonObject { ["ResourceId"] = new JsonArray(new JsonObject { ["Value"] = "{id}" }) } }),
            ("for_each", new JsonObject { ["service"] = "ec2", ["action"] = "DescribeVpcs", ["items"] = "//vpcSet/item", ["field"] = "id" })));
    }

    [Theory]
    [InlineData("/my-bucket/secrets.txt", null)]           // an object
    [InlineData("/my-bucket", "uploads")]                   // not a setting
    [InlineData("/my-bucket", null)]                        // the bucket's objects
    public void S3_reads_the_bucket_list_and_bucket_settings_never_objects(string path, string? subresource)
    {
        var parameters = subresource is null ? null : new JsonObject { [subresource] = "" };
        Assert.NotEmpty(Problems(("service", "s3"), ("action", "GetBucketPolicy"), ("path", path), ("items", "//x"), ("params", parameters)));
        Assert.Empty(Problems(("service", "s3"), ("action", "GetBucketPolicy"), ("path", "/my-bucket"), ("items", "//x"), ("params", new JsonObject { ["policy"] = "" })));
    }

    [Fact]
    public void A_rest_post_is_refused_unless_the_service_answers_it_as_a_read()
    {
        Assert.NotEmpty(Problems(("service", "lambda"), ("action", "ListFunctions"), ("path", "/2015-03-31/functions/x/invocations"), ("method", "post")));
        Assert.Empty(Problems(("service", "securityhub"), ("action", "GetFindings"), ("path", "/findings"), ("method", "post")));
    }

    private const string UsersPage1 = """
        <ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult>
          <Users><member><UserName>alice</UserName></member><member><UserName>bob</UserName></member></Users>
          <IsTruncated>true</IsTruncated><Marker>m2</Marker>
        </ListUsersResult></ListUsersResponse>
        """;

    private const string UsersPage2 = """
        <ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult>
          <Users><member><UserName>carol</UserName></member></Users><IsTruncated>false</IsTruncated>
        </ListUsersResult></ListUsersResponse>
        """;

    [Fact]
    public async Task A_query_api_is_a_signed_form_post_paged_by_its_marker()
    {
        var aws = new FakeAws((_, body) => FakeAws.Xml(body.Contains("Marker=m2", StringComparison.Ordinal) ? UsersPage2 : UsersPage1));

        var result = await Run(aws, ("service", "iam"), ("action", "ListUsers"), ("items", "//Users/member"));

        Assert.Equal("ok", result.State);
        Assert.Equal(new[] { "alice", "bob", "carol" }, result.Rows.Select(r => r["UserName"]!.ToString()));
        Assert.All(result.Rows, r => Assert.Equal(("own", "eu-central-1"), (r["_account"]!.ToString(), r["_region"]!.ToString())));
        Assert.All(aws.Sent, s => Assert.Equal("iam.amazonaws.com", s.Host));   // a global service: one host, whatever the regions
        Assert.Contains("Action=ListUsers&Version=2010-05-08", aws.Sent[0].Body, StringComparison.Ordinal);
        Assert.Contains("/us-east-1/iam/aws4_request", aws.Sent[0].Authorization, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_account_and_region_is_read_and_one_that_fails_makes_the_read_partial()
    {
        var aws = new FakeAws((request, _) => request.RequestUri!.Host.StartsWith("ec2.eu-west-1", StringComparison.Ordinal)
                ? FakeAws.Xml("<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>", HttpStatusCode.Forbidden)
                : FakeAws.Xml("<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet></DescribeVpcsResponse>"),
            accounts: ["111111111111", "222222222222"], regions: ["eu-central-1", "eu-west-1"], refusedAccount: "222222222222");

        var result = await Run(aws, ("service", "ec2"), ("action", "DescribeVpcs"), ("items", "//vpcSet/item"));

        Assert.Equal("partial", result.State);
        var place = Assert.Single(result.Rows);
        Assert.Equal(("111111111111", "eu-central-1"), (place["_account"]!.ToString(), place["_region"]!.ToString()));
        Assert.Contains("3 of 4 places failed", result.Reason, StringComparison.Ordinal);
        Assert.Contains("UnauthorizedOperation", result.Reason, StringComparison.Ordinal);
        Assert.Contains("AccessDenied", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_page_that_says_more_follow_without_a_token_where_the_rule_reads_it_is_cut_short()
    {
        // EC2 writes nextToken; a rule that looks for NextToken would stop on page one and call it complete.
        var aws = new FakeAws((_, body) => FakeAws.Xml(body.Contains("NextToken=t2", StringComparison.Ordinal)
            ? "<R><vpcSet><item><vpcId>vpc-2</vpcId></item></vpcSet></R>"
            : "<R><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet><nextToken>t2</nextToken></R>"));

        var right = await Run(aws, ("service", "ec2"), ("action", "DescribeVpcs"), ("items", "//vpcSet/item"));
        var wrong = await Run(aws, ("service", "ec2"), ("action", "DescribeVpcs"), ("items", "//vpcSet/item"),
            ("next", new JsonObject { ["from"] = "//NextToken", ["to"] = "NextToken" }));

        Assert.Equal(("ok", 2), (right.State, right.Rows.Count));
        Assert.Equal("partial", wrong.State);
    }

    [Fact]
    public async Task A_json_api_names_its_action_in_the_target_and_follows_the_rules_next()
    {
        var aws = new FakeAws((_, body) => StubHandler.Json(body.Contains("\"Marker\":\"k2\"", StringComparison.Ordinal)
            ? """{ "Keys": [ { "KeyId": "k2" } ], "Truncated": false }"""
            : """{ "Keys": [ { "KeyId": "k1" } ], "Truncated": true, "NextMarker": "k2" }"""));

        var unpaged = await Run(aws, ("service", "kms"), ("action", "ListKeys"), ("items", "Keys"));
        var paged = await Run(aws, ("service", "kms"), ("action", "ListKeys"), ("items", "Keys"), ("next", new JsonObject { ["from"] = "NextMarker", ["to"] = "Marker" }));

        Assert.Equal("partial", unpaged.State);   // KMS pages by NextMarker, not the usual NextToken
        Assert.Equal(new[] { "k1", "k2" }, paged.Rows.Select(r => r["KeyId"]!.ToString()));
        Assert.Equal("TrentService.ListKeys", aws.Sent[0].Target);
    }

    [Fact]
    public async Task Secrets_in_aws_answers_are_masked()
    {
        var aws = new FakeAws((_, _) => StubHandler.Json("""
            { "Functions": [ { "FunctionName": "f1", "Environment": { "Variables": { "DB_PASSWORD": "hunter2" } },
                               "Url": "https://x.lambda-url.example.org/?X-Amz-Signature=abc" } ] }
            """));

        var result = await Run(aws, ("service", "lambda"), ("action", "ListFunctions"), ("path", "/2015-03-31/functions/"), ("items", "Functions"));

        var row = Assert.Single(result.Rows);
        Assert.Equal("set", row["Environment"]!.ToString());
        Assert.DoesNotContain("abc", row["Url"]!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task One_request_per_object_goes_to_that_objects_own_account_and_region()
    {
        var aws = new FakeAws((request, body) =>
        {
            if (body.Contains("Action=ListUsers", StringComparison.Ordinal))
                return FakeAws.Xml(UsersPage2.Replace("carol", request.Headers.GetValues("X-Amz-Security-Token").Single() == "token-111111111111" ? "alice" : "bob", StringComparison.Ordinal));
            if (body.Contains("UserName=bob", StringComparison.Ordinal))
                return FakeAws.Xml("<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>gone</Message></Error></ErrorResponse>", HttpStatusCode.NotFound);
            return FakeAws.Xml("<R><AttachedPolicies><member><PolicyName>AdministratorAccess</PolicyName></member></AttachedPolicies></R>");
        }, accounts: ["111111111111", "222222222222"]);

        var result = await Run(aws, ("service", "iam"), ("action", "ListAttachedUserPolicies"), ("items", "//AttachedPolicies/member"),
            ("params", new JsonObject { ["UserName"] = "{UserName}" }), ("missing", "empty"),
            ("for_each", new JsonObject { ["service"] = "iam", ["action"] = "ListUsers", ["items"] = "//Users/member", ["field"] = "UserName" }));

        Assert.Equal("ok", result.State);   // bob has none: an answer, not a cut-short read
        var row = Assert.Single(result.Rows);
        Assert.Equal(("alice", "111111111111"), (row["parent"]!["UserName"]!.ToString(), row["_account"]!.ToString()));
        Assert.Contains("1 of 2 objects have none", result.Reason, StringComparison.Ordinal);
        // alice's policies were asked in alice's account, with that account's credentials.
        Assert.Contains(aws.Sent, s => s.Body.Contains("UserName=alice", StringComparison.Ordinal) && s.Authorization.Contains("AKIDEXAMPLE", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_bucket_policy_is_one_row_holding_the_document()
    {
        var aws = new FakeAws((_, _) => StubHandler.Json("""{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": "*" } ] }"""));

        var result = await Run(aws, ("service", "s3"), ("action", "GetBucketPolicy"), ("path", "/my-bucket"), ("items", "//x"), ("params", new JsonObject { ["policy"] = "" }));

        Assert.Equal("*", Assert.Single(result.Rows)["Policy"]!["Statement"]![0]!["Principal"]!.ToString());
        Assert.Equal("s3.eu-central-1.amazonaws.com", aws.Sent[0].Host);
        Assert.StartsWith("/my-bucket?policy|", aws.Sent[0].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Any_token_or_marker_the_answer_gives_means_more_unless_it_echoes_the_request()
    {
        // DynamoDB pages by LastEvaluatedTableName: without the rule's next, 100 tables of 150 must not read as complete.
        var tables = new FakeAws((_, _) => StubHandler.Json("""{ "TableNames": [ "t1" ], "LastEvaluatedTableName": "t1" }"""));
        // Route 53 echoes the Marker it was sent; the page after it is the last.
        var zones = new FakeAws((request, _) => FakeAws.Xml(request.RequestUri!.Query.Contains("marker=z2", StringComparison.Ordinal)
            ? "<ListHostedZonesResponse><HostedZones><HostedZone><Id>z2</Id></HostedZone></HostedZones><Marker>z2</Marker><IsTruncated>false</IsTruncated></ListHostedZonesResponse>"
            : "<ListHostedZonesResponse><HostedZones><HostedZone><Id>z1</Id></HostedZone></HostedZones><IsTruncated>true</IsTruncated><NextMarker>z2</NextMarker></ListHostedZonesResponse>"));

        var listed = await Run(tables, ("service", "dynamodb"), ("action", "ListTables"), ("items", "TableNames"));
        var paged = await Run(zones, ("service", "route53"), ("action", "ListHostedZones"), ("path", "/2013-04-01/hostedzone"), ("items", "//HostedZone"),
            ("next", new JsonObject { ["from"] = "//NextMarker", ["to"] = "marker" }));

        Assert.Equal("partial", listed.State);
        Assert.Equal(("ok", 2), (paged.State, paged.Rows.Count));
    }

    [Fact]
    public async Task A_bare_404_is_no_answer_and_a_coded_one_is_an_object_without_the_setting()
    {
        var aws = new FakeAws((_, body) => body.Contains("Action=ListUsers", StringComparison.Ordinal)
            ? FakeAws.Xml(UsersPage2)
            : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("") });

        var result = await Run(aws, ("service", "iam"), ("action", "ListAttachedUserPolicies"), ("items", "//AttachedPolicies/member"),
            ("params", new JsonObject { ["UserName"] = "{UserName}" }), ("missing", "empty"),
            ("for_each", new JsonObject { ["service"] = "iam", ["action"] = "ListUsers", ["items"] = "//Users/member", ["field"] = "UserName" }));

        Assert.Equal("failed", result.State);   // a wrong path looks just like this
    }

    [Fact]
    public async Task A_cloudtrail_event_is_read_as_the_object_it_holds_its_credentials_masked()
    {
        var aws = new FakeAws((_, _) => StubHandler.Json("""
            { "Events": [ { "EventName": "AssumeRole",
                "CloudTrailEvent": "{\"eventName\":\"AssumeRole\",\"responseElements\":{\"credentials\":{\"accessKeyId\":\"ASIAEXAMPLE\",\"sessionToken\":\"IQoJb3Jp\"}}}" } ] }
            """));

        var result = await Run(aws, ("service", "cloudtrail"), ("action", "LookupEvents"), ("items", "Events"));

        var trail = Assert.Single(result.Rows)["CloudTrailEvent"]!;
        Assert.Equal("AssumeRole", trail["eventName"]!.ToString());
        Assert.Equal("set", trail["responseElements"]!["credentials"]!["sessionToken"]!.ToString());
        Assert.DoesNotContain("IQoJb3Jp", result.Rows[0].ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_bucket_list_is_read_once_at_home_and_each_bucket_in_its_own_region()
    {
        var aws = new FakeAws((request, _) => request.RequestUri!.AbsolutePath == "/"
                ? FakeAws.Xml("<ListAllMyBucketsResult><Buckets><Bucket><Name>logs</Name><BucketRegion>eu-west-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>")
                : FakeAws.Xml("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
            regions: ["eu-central-1", "eu-west-1", "us-east-1"]);

        var result = await Run(aws, ("service", "s3"), ("action", "GetBucketVersioning"), ("path", "/{Name}"), ("items", "/VersioningConfiguration"),
            ("params", new JsonObject { ["versioning"] = "" }),
            ("for_each", new JsonObject { ["service"] = "s3", ["action"] = "ListBuckets", ["path"] = "/", ["items"] = "//Bucket", ["field"] = "Name" }));

        Assert.Equal("ok", result.State);
        Assert.Equal(["s3.eu-central-1.amazonaws.com", "s3.eu-west-1.amazonaws.com"], aws.Sent.Select(s => s.Host));
        Assert.Equal("Enabled", Assert.Single(result.Rows)["Status"]!.ToString());
    }

    [Fact]
    public async Task A_token_that_is_part_of_the_answer_is_not_a_next_page()
    {
        var aws = new FakeAws((_, _) => StubHandler.Json("""{ "WebACL": { "Name": "edge", "Rules": [] }, "LockToken": "a1b2" }"""));

        var result = await Run(aws, ("service", "wafv2"), ("action", "GetWebACL"), ("items", "WebACL"), ("params", new JsonObject { ["Name"] = "edge", ["Scope"] = "REGIONAL", ["Id"] = "x" }));

        Assert.Equal("ok", result.State);
    }

    [Fact]
    public async Task A_rest_error_named_in_its_header_is_read_and_a_missing_policy_is_an_answer()
    {
        var aws = new FakeAws((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath == "/2015-03-31/functions/")
                return StubHandler.Json("""{ "Functions": [ { "FunctionName": "f1" }, { "FunctionName": "f2" } ] }""");
            if (request.RequestUri.AbsolutePath.Contains("/f2/", StringComparison.Ordinal))
                return StubHandler.Json("""{ "Policy": "{\"Statement\":[{\"Principal\":\"*\"}]}" }""");
            var missing = new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("""{ "Message": "no policy" }""") };
            missing.Headers.TryAddWithoutValidation("x-amzn-ErrorType", "ResourceNotFoundException:http://internal.amazon.com/coral/");
            return missing;
        });

        var result = await Run(aws, ("service", "lambda"), ("action", "GetPolicy"), ("path", "/2015-03-31/functions/{FunctionName}/policy"), ("missing", "empty"),
            ("for_each", new JsonObject { ["service"] = "lambda", ["action"] = "ListFunctions", ["path"] = "/2015-03-31/functions/", ["items"] = "Functions", ["field"] = "FunctionName" }));

        Assert.Equal("ok", result.State);
        var policy = Assert.Single(result.Rows)["Policy"]!;
        Assert.IsAssignableFrom<JsonValue>(policy);   // a policy document stays the text rules match on
        Assert.Contains("\"Principal\":\"*\"", policy.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/clusters/a/node-groups/%2e%2e", false)]   // collapses to another operation
    [InlineData("/clusters/a/node-groups/..", false)]
    [InlineData("/clusters/a%2fb/node-groups/x", false)]
    [InlineData("/clusters/arn%3Aaws%3Aeks/node-groups/ng-1", true)]
    [InlineData("/clusters/prod/node-groups/ng-1", true)]
    public void A_rest_path_segment_is_plain(string path, bool allowed) =>
        Assert.Equal(allowed, AwsServices.IsPath(AwsServices.Rest["eks"]["DescribeNodegroup"], path));

    [Theory]
    [InlineData("DescribeAssociation")]
    [InlineData("GetMaintenanceWindowTask")]
    [InlineData("DescribeAutomationExecutions")]
    public void Reads_whose_parameters_carry_command_text_are_refused(string action) => Assert.NotNull(AwsServices.ActionProblem(action));

    [Fact]
    public void An_s3_setting_is_read_by_its_own_subresource()
    {
        Assert.NotEmpty(Problems(("service", "s3"), ("action", "GetBucketPolicy"), ("path", "/b"), ("items", "//x"), ("params", new JsonObject { ["acl"] = "" })));
    }

    [Fact]
    public async Task The_same_next_token_twice_is_a_cut_short_read()
    {
        var aws = new FakeAws((_, _) => FakeAws.Xml("<R><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet><nextToken>again</nextToken></R>"));

        var result = await Run(aws, ("service", "ec2"), ("action", "DescribeVpcs"), ("items", "//vpcSet/item"));

        Assert.Equal("partial", result.State);
    }
}
