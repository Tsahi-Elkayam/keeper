using Keeper.Integrations;

namespace Keeper.Integrations.Tests;

/// <summary>'keeper config export|import integration-types': a byte-for-byte copy that never leaves a folder that would not load.</summary>
public sealed class IntegrationTypeFilesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-type-files-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Type(string id) => $"""
        schema: keeper.integration-types/1
        types:
          - id: {id}
            description: {id} test type
            protocols: [http]
            auth: [api-key-header]
            hosts: ['{id}.example.com']
        """;

    private string Folder(string name, params (string File, string Yaml)[] files)
    {
        var folder = Path.Combine(_dir, name);
        Directory.CreateDirectory(folder);
        foreach (var (file, yaml) in files)
            File.WriteAllText(Path.Combine(folder, file), yaml);
        return folder;
    }

    [Fact]
    public void Copy_writes_new_and_changed_files_and_leaves_the_rest()
    {
        var from = Folder("from", ("a.yaml", Type("alpha")), ("b.yaml", Type("beta")), ("c.yaml", Type("gamma")), ("notes.txt", "not a type"));
        var to = Folder("to", ("b.yaml", Type("beta")), ("c.yaml", Type("gamma").Replace("gamma test", "gamma old", StringComparison.Ordinal)), ("z.yaml", Type("zeta")));

        var result = IntegrationTypeFiles.Copy(from, to);

        Assert.Equal(["a.yaml"], result.Added);
        Assert.Equal(["c.yaml"], result.Changed);
        Assert.Equal(["b.yaml"], result.Unchanged);
        Assert.Equal(["z.yaml"], result.OnlyInTarget);
        Assert.Equal(File.ReadAllBytes(Path.Combine(from, "c.yaml")), File.ReadAllBytes(Path.Combine(to, "c.yaml")));
        Assert.False(File.Exists(Path.Combine(to, "notes.txt")));
        Assert.Empty(Directory.EnumerateFiles(to, "*.tmp"));

        var again = IntegrationTypeFiles.Copy(from, to);   // idempotent
        Assert.Equal(0, again.Written);
    }

    [Fact]
    public void Copy_into_a_missing_folder_creates_it()
    {
        var from = Folder("from", ("a.yaml", Type("alpha")));
        var to = Path.Combine(_dir, "config", "integration-types");

        var result = IntegrationTypeFiles.Copy(from, to);

        Assert.Equal(["a.yaml"], result.Added);
        Assert.True(File.Exists(Path.Combine(to, "a.yaml")));
    }

    [Fact]
    public void Nothing_is_written_when_one_file_is_not_valid()
    {
        var from = Folder("from", ("a.yaml", Type("alpha")), ("b.yaml", Type("beta").Replace("hosts:", "hostz:", StringComparison.Ordinal)));
        var to = Folder("to");

        var ex = Assert.Throws<IntegrationException>(() => IntegrationTypeFiles.Copy(from, to));

        Assert.Contains("b.yaml", ex.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.EnumerateFiles(to));
    }

    [Fact]
    public void Nothing_is_written_when_the_result_defines_a_type_twice()
    {
        // The incoming file is valid alone, but the target keeps another file with the same id.
        var from = Folder("from", ("new.yaml", Type("alpha")));
        var to = Folder("to", ("old.yaml", Type("alpha")));

        var ex = Assert.Throws<IntegrationException>(() => IntegrationTypeFiles.Copy(from, to));

        Assert.Contains("also defined", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(to, "new.yaml")));
    }

    [Fact]
    public void A_file_may_not_replace_a_built_in_type()
    {
        var from = Folder("from", ("ldap.yaml", Type("ldap")));
        var to = Folder("to");

        Assert.Throws<IntegrationException>(() => IntegrationTypeFiles.Copy(from, to));
        Assert.Empty(Directory.EnumerateFiles(to));
    }
}
