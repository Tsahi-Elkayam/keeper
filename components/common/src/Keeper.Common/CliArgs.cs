namespace Keeper.Common;

/// <summary>
/// The argument parser every keeper binary shares: positional words, --name value, --name=value,
/// and declared flags (--name with no value).
/// </summary>
public sealed class CliArgs
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _positional = [];

    public CliArgs(IReadOnlyList<string> args, IReadOnlyCollection<string>? flags = null)
    {
        flags ??= [];
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal) || arg.Length == 2)
            {
                _positional.Add(arg);
                continue;
            }

            var name = arg[2..];
            var equals = name.IndexOf('=', StringComparison.Ordinal);
            if (equals >= 0)
                _options[name[..equals]] = name[(equals + 1)..];
            else if (flags.Contains(name, StringComparer.OrdinalIgnoreCase))
                _options[name] = null;
            else if (i + 1 < args.Count)
                _options[name] = args[++i];
            else
                throw new ArgumentException($"--{name} needs a value.");
        }
    }

    public IReadOnlyList<string> Positional => _positional;

    public IReadOnlyDictionary<string, string?> Options => _options;

    public bool Has(string name) => _options.ContainsKey(name);

    public string? Get(string name) => _options.TryGetValue(name, out var value) ? value : null;

    public string Require(string name) =>
        Get(name) is { Length: > 0 } value ? value : throw new ArgumentException($"--{name} is required.");

    /// <summary>The positional word at <paramref name="index"/>, or null.</summary>
    public string? At(int index) => index < _positional.Count ? _positional[index] : null;
}
