using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Store;

namespace Keeper.Queue.Tests;

/// <summary>A handler that writes a note; "boom" is refused, to test the failure path.</summary>
internal sealed class NoteHandler : IRequestHandler
{
    public string Kind => "test.note";

    public void Apply(RequestContext context)
    {
        var text = Payload.Required(context.Request.Payload, "text");
        if (text == "boom")
            throw new RequestException("boom is not a note.");
        context.Execute("INSERT INTO note (text, actor) VALUES (:t, :a);", (":t", text), (":a", context.Request.SubmittedBy));
    }
}

/// <summary>A handler that reads a file the request points at.</summary>
internal sealed class FileNoteHandler : IRequestHandler
{
    public string Kind => "test.file-note";

    public void Apply(RequestContext context)
    {
        var file = Payload.VerifiedFile(context);
        context.Execute("INSERT INTO note (text, actor, from_file) VALUES (:t, :a, :f);",
            (":t", File.ReadAllText(file)), (":a", context.Request.SubmittedBy), (":f", Path.GetFileName(file)));
    }
}

public sealed class QueueManagerTests : IDisposable
{
    private static readonly MigrationSet Notes = MigrationSet.FromResources("notes", typeof(QueueManagerTests).Assembly, "notes/");
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, Notes];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;
    private readonly Database _db;

    public QueueManagerTests()
    {
        _db = new Database(Path.Combine(_dir, "data", "keeper.db"));
        using var connection = _db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string DataDir => Path.Combine(_dir, "data");

    private string SpoolDir => Path.Combine(DataDir, "spool");

    private QueueManager Manager() =>
        new(_db, SpoolDir, DataDir, Schemas, [new NoteHandler(), new FileNoteHandler()]);

    private string Submit(string kind, string payloadJson, string reason = "test")
    {
        using var payload = JsonDocument.Parse(payloadJson);
        return new RequestWriter(SpoolDir).Submit(kind, reason, payload.RootElement.Clone(), @"TEST\user");
    }

    private object? Scalar(string sql)
    {
        using var connection = _db.OpenReadOnly();
        return Sql.Scalar(connection, sql);
    }

    private string[] Files(string folder) => Directory.GetFiles(Path.Combine(SpoolDir, folder));

    [Fact]
    public void A_queued_request_is_applied_and_audited()
    {
        var id = Submit("test.note", """{ "text": "hello" }""");

        var report = Manager().DrainOnce();

        Assert.Equal(new QueueReport(1, 0, 0), report);
        Assert.Equal("hello", Scalar("SELECT text FROM note"));
        Assert.Equal("done", Scalar($"SELECT state FROM request WHERE request_id = '{id}'"));
        Assert.Single(Files(Spool.Done));
        Assert.Empty(Files(Spool.Queue));
        Assert.Empty(Files(Spool.Work));
    }

    [Fact]
    public void A_refused_request_goes_to_failed_with_the_reason_and_writes_nothing()
    {
        var id = Submit("test.note", """{ "text": "boom" }""");

        var report = Manager().DrainOnce();

        Assert.Equal(1, report.Failed);
        Assert.Equal(0L, Scalar("SELECT COUNT(*) FROM note"));
        Assert.Contains("boom is not a note", File.ReadAllText(Assert.Single(Files(Spool.Failed))), StringComparison.Ordinal);
        Assert.Equal("failed", Scalar($"SELECT state FROM request WHERE request_id = '{id}'"));
    }

    [Fact]
    public void An_unknown_kind_fails()
    {
        Submit("drop-everything", "{}");

        Assert.Equal(1, Manager().DrainOnce().Failed);
    }

    [Fact]
    public void A_request_without_a_reason_is_refused()
    {
        Submit("test.note", """{ "text": "hello" }""", reason: "");

        Assert.Equal(1, Manager().DrainOnce().Failed);
        Assert.Equal(0L, Scalar("SELECT COUNT(*) FROM note"));
    }

    [Fact]
    public void A_request_is_never_applied_twice()
    {
        Submit("test.note", """{ "text": "once" }""");
        Manager().DrainOnce();

        // Put the request back in work\, as a crash between commit and move would leave it.
        var done = Assert.Single(Files(Spool.Done));
        var original = JsonNode.Parse(File.ReadAllText(done))!["request"]!.ToJsonString();
        File.WriteAllText(Path.Combine(SpoolDir, Spool.Work, Path.GetFileName(done)), original);

        var report = Manager().DrainOnce();

        Assert.Equal(new QueueReport(0, 0, 1), report);
        Assert.Equal(1L, Scalar("SELECT COUNT(*) FROM note"));
    }

    [Fact]
    public void Requests_apply_in_the_order_they_were_submitted()
    {
        for (var i = 0; i < 20; i++)
            Submit("test.note", $$"""{ "text": "n{{i:D2}}" }""");

        Manager().DrainOnce();

        using var connection = _db.OpenReadOnly();
        var texts = Sql.Rows(connection, "SELECT text FROM note ORDER BY note_id").Select(r => (string)r["text"]!).ToList();
        Assert.Equal(Enumerable.Range(0, 20).Select(i => $"n{i:D2}"), texts);
    }

    [Fact]
    public void A_second_writer_is_refused_while_the_lock_is_held()
    {
        Spool.EnsureFolders(SpoolDir);
        using var held = new FileStream(Path.Combine(SpoolDir, "writer.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        Assert.Throws<QueueBusyException>(() => Manager().DrainOnce());
    }

    [Fact]
    public void A_store_behind_the_build_is_refused()
    {
        var other = MigrationSet.FromResources("notes", typeof(QueueManagerTests).Assembly, "notes/") with { Component = "unapplied" };
        var manager = new QueueManager(_db, SpoolDir, DataDir, [QueueSchema.Migrations, Notes, other], [new NoteHandler()]);

        Assert.Throws<StoreException>(() => manager.DrainOnce());
    }

    [Fact]
    public void A_file_reference_is_applied_when_its_hash_matches()
    {
        var file = Path.Combine(DataDir, "runs", "r1", "note.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "from a file");
        Submit("test.file-note", $$"""{ "file": "runs/r1/note.txt", "sha256": "{{Hashing.Sha256File(file)}}" }""");

        Assert.Equal(1, Manager().DrainOnce().Done);
        Assert.Equal("from a file", Scalar("SELECT text FROM note"));
    }

    [Fact]
    public void A_file_changed_after_submit_is_refused()
    {
        var file = Path.Combine(DataDir, "runs", "r1", "note.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "original");
        Submit("test.file-note", $$"""{ "file": "runs/r1/note.txt", "sha256": "{{Hashing.Sha256File(file)}}" }""");
        File.WriteAllText(file, "swapped");

        Assert.Equal(1, Manager().DrainOnce().Failed);
        Assert.Equal(0L, Scalar("SELECT COUNT(*) FROM note"));
    }

    [Fact]
    public void A_file_outside_the_data_folder_is_refused()
    {
        var outside = Path.Combine(_dir, "outside.txt");
        File.WriteAllText(outside, "secret");
        Submit("test.file-note", $$"""{ "file": "../outside.txt", "sha256": "{{Hashing.Sha256File(outside)}}" }""");

        Assert.Equal(1, Manager().DrainOnce().Failed);
        Assert.Equal(0L, Scalar("SELECT COUNT(*) FROM note"));
    }
}
