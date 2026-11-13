using System.Text;

namespace Keeper.Integrations;

/// <summary>
/// Reads a secret from the keyboard without echoing it. Never from an argument (process lists and shell
/// history keep those) and never from redirected input: with no person at the keyboard, it refuses.
/// </summary>
public static class SecretPrompt
{
    public static string Read(string prompt)
    {
        if (Console.IsInputRedirected || !Environment.UserInteractive)
            throw new IntegrationException("A secret can only be typed at the keyboard; this session has no interactive input.");

        Console.Error.Write(prompt);
        var secret = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (secret.Length > 0)
                    secret.Length--;
                continue;
            }
            if (key.Key == ConsoleKey.Escape)
                throw new IntegrationException("Cancelled.");
            if (!char.IsControl(key.KeyChar))
                secret.Append(key.KeyChar);
        }
        Console.Error.WriteLine();
        if (secret.Length == 0)
            throw new IntegrationException("Nothing was typed.");
        return secret.ToString();
    }
}
