using Keeper.Common;
using Keeper.Composition;
using Keeper.Home;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-db: the store's lifecycle. init and migrate only report what they would do unless --apply.
try
{
    var cli = new CliArgs(args, flags: ["apply"]);
    if (cli.Help)
        return Usage(asked: true);
    var command = cli.At(0) ?? "status";
    var (paths, db) = Composition.Locate(cli);
    var schemas = Composition.Schemas;

    return command switch
    {
        "status" => Status(db, schemas),
        "init" or "migrate" => Migrate(db, paths, schemas, cli.Has("apply"), command == "init"),
        "backup" => Backup(db, paths),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is SettingsException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static int Status(Database db, IReadOnlyList<MigrationSet> schemas)
{
    Console.WriteLine($"Store: {db.DbFile}");
    if (!db.Exists)
    {
        Console.WriteLine("Not created yet. Run 'keeper db init --apply' (or 'keeper setup --apply').");
        return ExitCodes.NoData;
    }
    using var connection = db.OpenReadOnly();
    var status = SchemaManager.Status(connection, schemas);
    foreach (var s in status)
        Console.WriteLine($"  {s.Component,-14} version {s.Current} of {s.Latest}{(s.UpToDate ? "" : "  <- run 'keeper db migrate --apply'")}");
    return status.All(s => s.UpToDate) ? ExitCodes.Ok : ExitCodes.Failed;
}

static int Migrate(Database db, KeeperPaths paths, IReadOnlyList<MigrationSet> schemas, bool apply, bool init)
{
    if (!init && !db.Exists)
        throw new ArgumentException($"No store at {db.DbFile}. Run 'keeper db init --apply'.");
    if (init && db.Exists)
    {
        Console.WriteLine($"A store already exists at {db.DbFile}. 'keeper db migrate' brings it up to date.");
        return ExitCodes.Ok;
    }

    IReadOnlyList<(MigrationSet Set, Migration Migration)> pending;
    if (db.Exists)
    {
        using var read = db.OpenReadOnly();
        pending = SchemaManager.Pending(read, schemas);
    }
    else
    {
        pending = SchemaManager.Ordered(schemas).SelectMany(s => s.Migrations.Select(m => (s, m))).ToList();
    }

    if (pending.Count == 0)
    {
        Console.WriteLine("Up to date.");
        return ExitCodes.Ok;
    }
    Console.WriteLine($"{(init ? "Creates" : "Migrates")} {db.DbFile}:");
    foreach (var (set, migration) in pending)
        Console.WriteLine($"  {set.Component,-14} {migration.Version:D3} {migration.Name}");
    if (!apply)
    {
        Console.WriteLine("Dry run: nothing changed. Re-run with --apply.");
        return ExitCodes.Ok;
    }

    if (db.Exists)
    {
        var backup = Path.Combine(paths.Backups, $"keeper-{Iso.Stamp(DateTimeOffset.UtcNow)}.db");
        db.BackupTo(backup);
        Console.WriteLine($"Backed up to {backup}");
    }
    using var connection = db.OpenReadWrite(create: true);
    var applied = SchemaManager.Apply(connection, schemas);
    Console.WriteLine($"Applied {applied} migration(s).");
    return ExitCodes.Ok;
}

static int Backup(Database db, KeeperPaths paths)
{
    var file = Path.Combine(paths.Backups, $"keeper-{Iso.Stamp(DateTimeOffset.UtcNow)}.db");
    db.BackupTo(file);
    Console.WriteLine($"Backed up to {file}");
    return ExitCodes.Ok;
}

static int Usage(bool asked = false) =>
    CliUsage.Print("""
        keeper-db - the store's lifecycle

          keeper-db status               every component's schema version
          keeper-db init [--apply]       create the store (dry run without --apply)
          keeper-db migrate [--apply]    apply pending migrations, backing up first
          keeper-db backup               copy the store into data\backups\
        """, asked);
