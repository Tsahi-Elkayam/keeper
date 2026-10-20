namespace Keeper.Common.Tests;

public sealed class DurationTests
{
    [Theory]
    [InlineData("30m", 30)]
    [InlineData("6h", 360)]
    [InlineData("1d", 1440)]
    [InlineData("2w", 20160)]
    public void Parses_short_durations(string text, int minutes)
    {
        Assert.Equal(TimeSpan.FromMinutes(minutes), Durations.Parse(text));
    }

    [Theory]
    [InlineData("")]
    [InlineData("d")]
    [InlineData("0d")]
    [InlineData("-1d")]
    [InlineData("5y")]
    public void Refuses_anything_else(string text)
    {
        Assert.False(Durations.TryParse(text, out _));
    }
}

public sealed class RedactorTests
{
    [Theory]
    [InlineData("password=Hunter2", "password=<redacted>")]
    [InlineData("\"client_secret\": \"abc123\"", "\"client_secret\": \"<redacted>\"")]
    [InlineData("Authorization: Bearer abc.def.ghi", "Authorization: Bearer <redacted>")]
    [InlineData("https://admin:Hunter2@host.example.org/api", "https://<redacted>@host.example.org/api")]
    public void Removes_what_looks_like_a_credential(string text, string expected)
    {
        Assert.Equal(expected, Redactor.Clean(text));
    }

    [Fact]
    public void Keeps_identifiers()
    {
        const string text = "dc1.example.org: user svc-backup has adminCount=1";

        Assert.Equal(text, Redactor.Clean(text));
    }
}

public sealed class PathGuardTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Resolves_a_relative_path_inside_the_folder()
    {
        Assert.Equal(Path.Combine(_dir, "a", "b.xml"), PathGuard.Resolve(_dir, Path.Combine("a", "b.xml")));
    }

    [Theory]
    [InlineData("..\\outside.xml")]
    [InlineData("../outside.xml")]
    [InlineData("a/../../outside.xml")]
    public void Refuses_a_path_that_leaves_the_folder(string relative)
    {
        Assert.Throws<UnauthorizedAccessException>(() => PathGuard.Resolve(_dir, relative));
    }

    [Fact]
    public void Refuses_an_absolute_path()
    {
        Assert.Throws<UnauthorizedAccessException>(() => PathGuard.Resolve(_dir, Path.GetTempPath()));
    }
}

public sealed class JsonLinesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed record Item(string Name, int Count);

    [Fact]
    public void Round_trips_records_one_per_line()
    {
        var file = Path.Combine(_dir, "items.jsonl");
        using (var writer = new JsonLinesWriter(file))
        {
            writer.Write(new Item("שרת", 1));
            writer.Write(new Item("two", 2));
        }

        var items = JsonLines.Read<Item>(file).ToList();

        Assert.Equal(new[] { new Item("שרת", 1), new Item("two", 2) }, items);
        Assert.Equal(2, File.ReadAllLines(file).Length);
    }

    [Fact]
    public void A_line_that_is_not_an_object_is_refused()
    {
        var file = Path.Combine(_dir, "bad.jsonl");
        File.WriteAllText(file, "[1,2]\n");

        Assert.Throws<FormatException>(() => JsonLines.Read(file).ToList());
    }
}
