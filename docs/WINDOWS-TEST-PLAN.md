# Testing Keeper on Windows

Keeper is Windows-first, but almost all of its development and testing so far has been on macOS, and its test suite
has also been run on Linux (aarch64, .NET 10): all projects pass there. **It has not yet been run on Windows.**
This is how to find out, in a Windows machine or VM.

## 1. One command

Install the .NET 10 SDK (`winget install Microsoft.DotNet.SDK.10`), copy or clone the repository, then in PowerShell:

```
powershell -ExecutionPolicy Bypass -File tools\windows-smoke.ps1
```
It runs every test project, builds the binary, sets up a throwaway Keeper home, adds the machine
itself as the only CIM target, scans it with `workstations`, `windows-baseline` and `windows-server`, loads and
tracks the results, lists what it found and builds the interactive page. Everything goes to `windows-smoke.log`.

## 2. What to look at

- **`dotnet test`.** Any failure is a Windows problem. Most likely suspects: path separators, file permissions
  (the vault key file, the private-home check), line endings, and the printer, SSH and SNMP tests that use local sockets.
- **The scans.** Never run before on any real machine. Expect some rules to come back *unknown* (a query the
  machine could not answer), and some to need WinRM: if the service is stopped, `winrm quickconfig` turns it on, or leave
  `cimProtocol=auto` to fall back to DCOM.
- **ARM.** The Fusion VM is Windows 11 ARM. If the CIM package has no arm64 build the scan will fail to start; that
  tells us the Windows readers need an arm64 answer, not that the rules are wrong.
- **The page.** Open `windows-smoke-ui.html` in a browser.

## 3. Then, on a domain

Run Keeper from a domain-joined Windows machine, add an `ldap` integration (`--auth negotiate`, endpoint your
domain) and a `cim` one, and run `keeper run`. The Windows packs find their hosts in Active Directory. To try a
single host first, give the `cim` integration `--option targets=<host>`: an explicit list overrides the directory.
