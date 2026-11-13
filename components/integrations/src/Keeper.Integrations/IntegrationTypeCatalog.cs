using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Keeper.Integrations;

/// <summary>
/// Integration types as data: the catalog built into keeper (integration-types.yaml, an embedded resource, so its
/// guards cannot be edited on disk) and the types a tenant adds in settings/integration-types/*.yaml. A tenant type
/// cannot replace a built-in one, and may only name protocols and auth kinds Keeper has code for.
/// </summary>
public static class IntegrationTypeCatalog
{
    public const string Schema = "keeper.integration-types/1";

    /// <summary>Protocols only built-in types use: Keeper's own store, imported files and host reads have meanings of their own.</summary>
    private static readonly string[] BuiltInOnlyProtocols = ["store", "file", "host"];

    private sealed class FileDto
    {
        public string? Schema { get; set; }
        public List<TypeDto>? Types { get; set; }
    }

    private sealed class TypeDto
    {
        public string? Id { get; set; }
        public string? Description { get; set; }
        public List<string>? Protocols { get; set; }
        public List<string>? Auth { get; set; }
        public List<string>? Hosts { get; set; }
        public string? Endpoint { get; set; }
        public string? EndpointPath { get; set; }
        public string? Resource { get; set; }
        public List<string>? ReadPosts { get; set; }
        public List<string>? ReadPaths { get; set; }
        public CommandDto? ReadCommand { get; set; }
    }

    private sealed class CommandDto
    {
        public string? Field { get; set; }
        public List<string>? Allowed { get; set; }
        public string? ParametersField { get; set; }
        public List<string>? DeniedParameters { get; set; }
    }

    // An unknown key is an error: a misspelt guard (readpaths) must not silently read everything. So is a key given
    // twice: which of two read lists applies must not be a parser's choice.
    private static readonly IDeserializer Reader = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .WithDuplicateKeyChecking()
        .Build();

    /// <summary>The catalog built into keeper.</summary>
    public static IReadOnlyList<IntegrationType> BuiltIn()
    {
        using var stream = typeof(IntegrationTypeCatalog).Assembly.GetManifestResourceStream("integrations/integration-types.yaml")
            ?? throw new InvalidOperationException("The built-in integration types are missing from Keeper.Integrations.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd(), "the built-in integration types", builtIn: null);
    }

    /// <summary>
    /// The types in one file. <paramref name="builtIn"/>: null for the built-in catalog itself; for a tenant file, the
    /// built-in types it may not replace and whose protocols bound what it may name.
    /// </summary>
    public static IReadOnlyList<IntegrationType> Parse(string yaml, string source, IReadOnlyList<IntegrationType>? builtIn)
    {
        FileDto file;
        try
        {
            file = Reader.Deserialize<FileDto>(yaml) ?? new FileDto();
        }
        catch (YamlException ex)
        {
            // YamlDotNet's own message is "Exception during deserialization"; what went wrong is in the inner one.
            var why = System.Text.RegularExpressions.Regex.Replace((ex.InnerException ?? ex).Message,
                @"Property '([^']*)' not found on type '[^']*'\.?", "'$1' is not a field of an integration type");
            throw new IntegrationException($"{source}, line {ex.Start.Line}: {why}");
        }
        if (file.Schema != Schema)
            throw new IntegrationException($"{source}: schema must be {Schema}.");
        var types = new List<IntegrationType>();
        foreach (var dto in file.Types ?? [])
        {
            if (dto is null)
                throw new IntegrationException($"{source}: an entry under types is empty.");
            var type = Build(dto, source, builtIn);
            if (types.Any(t => t.Id.Equals(type.Id, StringComparison.OrdinalIgnoreCase)))
                throw new IntegrationException($"{source}: integration type '{type.Id}' is listed twice.");
            types.Add(type);
        }
        return types;
    }

    private static IntegrationType Build(TypeDto dto, string source, IReadOnlyList<IntegrationType>? builtIn)
    {
        var id = dto.Id ?? throw new IntegrationException($"{source}: an integration type has no id.");
        string Where(string what) => $"{source}: integration type '{id}': {what}";
        if (!IntegrationTypes.IsValidId(id))
            throw new IntegrationException(Where("the id must be lower-case letters, digits and dashes"));
        if (string.IsNullOrWhiteSpace(dto.Description))
            throw new IntegrationException(Where("description is required"));
        if (dto.Protocols is not { Count: > 0 } protocols)
            throw new IntegrationException(Where("protocols lists the protocols its rules may use"));
        if (dto.Auth is not { Count: > 0 } auth)
            throw new IntegrationException(Where("auth lists the ways it may sign in"));
        foreach (var kind in auth.Where(k => !IntegrationTypes.SecretsFor.ContainsKey(k)))
            throw new IntegrationException(Where($"auth kind '{kind}' is not one Keeper can sign in with ({string.Join(", ", IntegrationTypes.SecretsFor.Keys)})"));
        if (builtIn is not null)
        {
            if (builtIn.Any(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))
                throw new IntegrationException(Where("a built-in type has this id; a tenant type adds a type, it cannot replace one"));
            var known = builtIn.SelectMany(t => t.Protocols).Except(BuiltInOnlyProtocols).ToHashSet(StringComparer.Ordinal);
            foreach (var protocol in protocols.Where(p => !known.Contains(p)))
                throw new IntegrationException(Where($"protocol '{protocol}' is not one a tenant type may use ({string.Join(", ", known.Order(StringComparer.Ordinal))})"));
        }
        var hosts = dto.Hosts ?? [];
        foreach (var host in hosts.Where(h => !IsHostPattern(h)))
            throw new IntegrationException(Where($"host '{host}' must be a host name or *.suffix of at least two labels (*.example.org), without a scheme, port or path"));
        if (builtIn is not null && hosts.Count == 0)
        {
            // Without a host list the endpoint may name any host. A tenant type may then sign in only the ways a
            // built-in type does without a host list: an Entra, AWS or Google token, or a password grant, exists only
            // behind one, and a type that dropped it would send that credential wherever its endpoint points.
            foreach (var protocol in protocols)
            {
                foreach (var kind in auth.Where(k => !builtIn.Any(t => t.AllowedHosts.Count == 0 && t.Protocols.Contains(protocol) && t.AuthKinds.Contains(k))))
                    throw new IntegrationException(Where($"auth kind '{kind}' over {protocol} needs hosts: the hosts its endpoint may name, " +
                                                         "so the credential cannot be sent anywhere else"));
            }
        }
        if (dto.Endpoint is { } endpoint)
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                throw new IntegrationException(Where($"endpoint '{endpoint}' must be an https URL"));
        }
        foreach (var path in (dto.ReadPosts ?? []).Concat(dto.ReadPaths ?? []).Append(dto.EndpointPath ?? "/").Where(p => !p.StartsWith('/')))
            throw new IntegrationException(Where($"path '{path}' must start with /"));
        Keeper.Runners.ReadCommand? command = null;
        if (dto.ReadCommand is { } c)
        {
            if (string.IsNullOrWhiteSpace(c.Field) || c.Allowed is not { Count: > 0 })
                throw new IntegrationException(Where("readCommand needs field and allowed"));
            command = new Keeper.Runners.ReadCommand(c.Field, c.Allowed)
            {
                ParametersField = c.ParametersField,
                DeniedParameters = c.DeniedParameters ?? [],
            };
        }
        var type = new IntegrationType(id, dto.Description.Trim(), protocols, auth, hosts, dto.Endpoint)
        {
            ReadPosts = dto.ReadPosts ?? [],
            ReadPaths = dto.ReadPaths ?? [],
            EndpointPath = dto.EndpointPath,
            ReadCommand = command,
            Resource = dto.Resource,
            Source = builtIn is null ? null : source,
        };
        if (dto.Endpoint is { } given && !type.AllowsHost(new Uri(given).Host))
            throw new IntegrationException(Where($"endpoint '{given}' is not on one of its own hosts"));
        return type;
    }

    private static bool IsHostPattern(string host)
    {
        var wildcard = host.StartsWith("*.", StringComparison.Ordinal);
        var labels = (wildcard ? host[2..] : host).Split('.');
        // *.com would let the credential go to any host under a top-level domain.
        return labels.Length >= (wildcard ? 2 : 1)
               && labels.All(label => label.Length > 0 && label.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-'));
    }
}
