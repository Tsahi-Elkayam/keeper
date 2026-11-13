using System.Text.Json.Nodes;

namespace Keeper.Rules.Tests;

public sealed class FieldPathTests
{
    private static readonly JsonNode Row = JsonNode.Parse("""
        {
          "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
          "user": { "company.name": "Example", "Mail": "a@example.org" },
          "value": [ { "user.company": "A" }, { "user.company": "B" } ],
          "plain": { "a": { "b": 1 } }
        }
        """)!;

    [Theory]
    [InlineData("""["@odata.type"]""", "#microsoft.graph.windows10CompliancePolicy")]
    [InlineData("""user.["company.name"]""", "Example")]
    [InlineData("""value[].["user.company"]""", "A|B")]
    [InlineData("plain.a.b", "1")]
    [InlineData("user.mail", "a@example.org")]   // names match case-insensitively
    [InlineData("""["no.such"]""", "")]
    public void A_quoted_name_may_hold_dots(string path, string expected)
    {
        Assert.Equal(expected, string.Join("|", FieldPath.Resolve(Row, path).Select(Values.Text)));
    }

    [Fact]
    public void Templates_take_quoted_names_too()
    {
        Assert.Equal("type #microsoft.graph.windows10CompliancePolicy", Templates.Render("""type {["@odata.type"]}""", Row));
    }
}
