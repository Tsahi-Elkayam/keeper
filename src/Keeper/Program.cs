using Keeper.Core;

// Exit codes: 0 = ran, 2 = settings problem, 3 = nothing was checked.
var settingsPath = Path.Combine(AppContext.BaseDirectory, "settings", "settings.json");

if (!File.Exists(settingsPath))
{
    Console.Error.WriteLine($"No settings at {settingsPath}");
    Console.Error.WriteLine(@"Copy settings\settings.example.json to settings\settings.json and edit it.");
    return 2;
}

KeeperSettings settings;
try
{
    settings = SettingsLoader.Load(settingsPath);
}
catch (SettingsException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 2;
}

Console.WriteLine($"Keeper {typeof(Finding).Assembly.GetName().Version} - tenant '{settings.TenantName}'");
Console.WriteLine($"Settings: {settingsPath}");
Console.WriteLine($"Data:     {SettingsLoader.ResolveDataPath(settings, settingsPath)}");

var enabled = settings.Connectors.Where(c => c.Enabled).ToList();
if (enabled.Count == 0)
{
    Console.WriteLine("Nothing checked: no connectors are enabled. No data is not the same as no problems.");
    return 3;
}

foreach (var connector in enabled)
    Console.WriteLine($"Connector '{connector.Type}' is enabled but not implemented yet - nothing collected.");
Console.WriteLine("Nothing checked: no connector is implemented yet.");
return 3;
