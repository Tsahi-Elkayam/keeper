using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.TestKit;

// demo-vault: adds or changes a demo value the tests use (see DemoVault) - a test tool, never part of the
// product build. The value is read from the console without being shown - or from standard input when it is
// redirected - so it is never written out anywhere but sealed in demo.vault.json.
//   dotnet run --project components\testkit\src\demo-vault -- set <name>
if (args is not ["set", var name] || name.Length == 0 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.'))
{
    Console.Error.WriteLine("demo-vault set <name>   seal a demo value under name (letters, digits, - and .); it is read without being shown");
    return 2;
}

var value = Console.IsInputRedirected ? Console.In.ReadLine() : ReadHidden($"value for {name}: ");
if (string.IsNullOrEmpty(value))
{
    Console.Error.WriteLine("No value given; nothing changed.");
    return 1;
}

var file = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Keeper.TestKit", DemoVault.FileName);
file = Path.GetFullPath(file);
var entries = File.Exists(file) ? JsonNode.Parse(File.ReadAllText(file)) as JsonObject ?? [] : [];
entries[name] = DemoVault.Seal(name, value);
var sorted = new JsonObject(entries.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => KeyValuePair.Create(e.Key, e.Value?.DeepClone())));
File.WriteAllText(file, sorted.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n", new UTF8Encoding(false));
Console.WriteLine($"{name} sealed in {file}.");
return 0;

static string ReadHidden(string prompt)
{
    Console.Write(prompt);
    var text = new StringBuilder();
    for (var key = Console.ReadKey(intercept: true); key.Key != ConsoleKey.Enter; key = Console.ReadKey(intercept: true))
    {
        if (key.Key == ConsoleKey.Backspace && text.Length > 0)
            text.Length--;
        else if (!char.IsControl(key.KeyChar))
            text.Append(key.KeyChar);
    }
    Console.WriteLine();
    return text.ToString();
}
