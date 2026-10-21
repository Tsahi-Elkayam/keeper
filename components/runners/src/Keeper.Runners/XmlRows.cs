using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace Keeper.Runners;

/// <summary>
/// XML as rows, for imported files and for APIs that answer in XML: the elements an XPath selects, each as an
/// object (attributes and child elements by name, repeated children as arrays, text as _text). Namespaces are
/// dropped, so //item finds the items of a document with a default namespace. No DTDs, no external entities.
/// </summary>
public static class XmlRows
{
    public const int DefaultMaxDepth = 32;

    public static XDocument Load(TextReader text, long maxCharacters)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = maxCharacters,
        };
        using var reader = XmlReader.Create(text, settings);
        var document = XDocument.Load(reader);
        foreach (var element in document.Descendants())
        {
            element.Name = element.Name.LocalName;
            element.Attributes().Where(a => a.IsNamespaceDeclaration).Remove();
            foreach (var attribute in element.Attributes().Where(a => a.Name.Namespace != XNamespace.None).ToList())
            {
                attribute.Remove();
                element.SetAttributeValue(attribute.Name.LocalName, attribute.Value);
            }
        }
        return document;
    }

    /// <param name="maxDepth">Elements nested deeper than this become their text.</param>
    public static List<JsonObject> Select(XDocument document, string xpath, int maxDepth = DefaultMaxDepth) =>
        [.. document.XPathSelectElements(xpath).Select(e => ToJson(e, 0, maxDepth))];

    /// <summary>The text of the first node an XPath selects (an element's text, or an attribute's value), or null.</summary>
    public static string? Value(XDocument document, string xpath) =>
        document.XPathEvaluate(xpath) switch
        {
            IEnumerable<object> nodes => nodes.FirstOrDefault() switch
            {
                XElement e => e.Value.Trim() is { Length: > 0 } t ? t : null,
                XAttribute a => a.Value,
                XText t => t.Value,
                _ => null,
            },
            string s when s.Length > 0 => s,
            double d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
            bool b => b ? "true" : "false",
            _ => null,
        };

    private static JsonObject ToJson(XElement element, int depth, int maxDepth)
    {
        var row = new JsonObject();
        foreach (var attribute in element.Attributes())
            row[attribute.Name.LocalName] = attribute.Value;

        foreach (var group in element.Elements().GroupBy(e => e.Name.LocalName))
        {
            // A child with attributes is an object too (<Properties cpassword="..."/>): as text alone its attributes
            // would be lost. A child with only text stays its text.
            var values = group.Select(child => (child.HasElements || child.HasAttributes) && depth < maxDepth
                    ? (JsonNode)ToJson(child, depth + 1, maxDepth)
                    : JsonValue.Create(child.Value.Trim()))
                .ToList();
            row[group.Key] = values.Count == 1 ? values[0] : new JsonArray([.. values]);
        }

        if (!element.HasElements && element.Value.Trim() is { Length: > 0 } text)
            row["_text"] = text;
        return row;
    }
}
