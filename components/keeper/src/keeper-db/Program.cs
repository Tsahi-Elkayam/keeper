using System.Globalization;
using Keeper.Core;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-db: the store's lifecycle. init and migrate only report what they would do unless --apply.
try
{
    var cli = new CliArgs(args, flags: ["apply"]);
    var command = cli.Positional.Count > 0 ? cli.Positional[0] : "status";
    var (_, paths) = KeeperContext.Load(cli);
    var db = new KeeperDb(paths.Database);

    return command switch
    {
        "status" => Status(db),
        "init" => Init(db, cli.Has("apply")),
        "migrate" => Migrate(db, paths, cli.Has("apply")),
        "backup" => Backup(db, paths),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is SettingsException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Failed;
}

static int Status(KeeperDb db)
{
    Console.WriteLine($"Store:    {db.DbFile}");
    if (!db.Exists)
    {
        Console.WriteLine("State:    not created. Run 'keeper-db init --apply'.");
        return ExitCodes.NoData;
    }

    using var connection = db.OpenReadOnly();
    var version = KeeperDb.Version(connection);
    Console.WriteLine($"Version:  {version} (this build: {Migrations.Latest})");
    if (version != Migrations.Latest)
    {
        Console.WriteLine("Run 'keeper-db migrate' before using the store.");
        return ExitCodes.Failed;
    }

    (string Label, string Sql)[] counts =
    [
        ("Systems", "SELECT COUNT(*) FROM system WHERE active = 1"),
        ("Runs", "SELECT COUNT(*) FROM run"),
        ("Active findings", "SELECT COUNT(*) FROM active_finding"),
        ("Failed writes", "SELECT COUNT(*) FROM request WHERE state = 'failed'"),
    ];
    foreach (var (label, sql) in counts)
        Console.WriteLine($"{label + ":",-17}{Sql.Scalar(connection, sql)}");
    return ExitCodes.Ok;
}

static int Init(KeeperDb db, bool apply)
{
    if (db.Exists)
    {
        Console.WriteLine($"A store already exists at {db.DbFile}. See 'keeper-db status' or 'keeper-db migrate'.");
        return ExitCodes.Ok;
    }

    Console.WriteLine($"Creates {db.DbFile} with {Migrations.Latest} migration(s):");
    Print(Migrations.All);
    if (!apply)
    {
        Console.WriteLine("Dry run: nothing changed. Re-run with --apply.");
        return ExitCodes.Ok;
    }

    using var connection = db.OpenReadWrite(create: true);
    Migrations.Apply(connection, Migrations.All);
    Console.WriteLine($"Created. Store is at version {KeeperDb.Version(connection)}.");
    return ExitCodes.Ok;
}

static int Migrate(KeeperDb db, KeeperPaths paths, bool apply)
{
    if (!db.Exists)
    {
        Console.Error.WriteLine($"No store at {db.DbFile}. Run 'keeper-db init --apply'.");
        return ExitCodes.Usage;
    }

    int current;
    using (var read = db.OpenReadOnly())
        current = KeeperDb.Version(read);

    if (current > Migrations.Latest)
    {
        Console.Error.WriteLine($"Store is at version {current}, newer than this build ({Migrations.Latest}). Use a newer build.");
        return ExitCodes.Failed;
    }

    var pending = Migrations.Pending(current);
    if (pending.Count == 0)
    {
        Console.WriteLine($"Up to date at version {current}.");
        return ExitCodes.Ok;
    }

    Console.WriteLine($"Store is at version {current}; {pending.Count} migration(s) pending:");
    Print(pending);
    if (!apply)
    {
        Console.WriteLine("Dry run: nothing changed. Re-run with --apply (the store is backed up first).");
        return ExitCodes.Ok;
    }

    var backup = BackupFile(paths);
    db.BackupTo(backup);
    Console.WriteLine($"Backed up to {backup}");

    using var connection = db.OpenReadWrite();
    Migrations.Apply(connection, pending);
    Console.WriteLine($"Store is at version {KeeperDb.Version(connection)}.");
    return ExitCodes.Ok;
}

static int Backup(KeeperDb db, KeeperPaths paths)
{
    var backup = BackupFile(paths);
    db.BackupTo(backup);
    Console.WriteLine($"Backed up to {backup}");
    return ExitCodes.Ok;
}

static string BackupFile(KeeperPaths paths) =>
    Path.Combine(paths.Backups, $"keeper-{DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}.db");

static void Print(IEnumerable<Migration> migrations)
{
    foreach (var migration in migrations)
        Console.WriteLine($"  {migration.Version.ToString("D3", CultureInfo.InvariantCulture)} {migration.Name}");
}

static int Usage()
{
    Console.Error.WriteLine("""
        keeper-db - the store's lifecycle

          keeper-db status               version, pending migrations, counts
          keeper-db init [--apply]       create the store (dry run without --apply)
          keeper-db migrate [--apply]    apply pending migrations, backing up first
          keeper-db backup               copy the store into data\backups\

          --settings <file>              default: settings\settings.json in the Keeper home (KEEPER_HOME)
        """);
    return ExitCodes.Usage;
}
