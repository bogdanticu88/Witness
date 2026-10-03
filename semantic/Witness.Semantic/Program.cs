using System.Text;
using System.Text.Json;
using Witness.Semantic;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

// witness-semantic: Roslyn-backed semantic queries over a read-only
// repository snapshot, one JSON request per line on stdin, one JSON response
// per line on stdout. Diagnostics go to stderr. It never writes to the
// repository, never runs MSBuild and never opens network connections.

const int MaxRequestBytes = 1024 * 1024;

string? refPacks = null;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--version":
            Console.WriteLine($"witness-semantic {typeof(Server).Assembly.GetName().Version?.ToString(3)} ({ProtocolInfo.Version})");
            return 0;
        case "--ref-packs" when i + 1 < args.Length:
            refPacks = args[++i];
            break;
        case "--help" or "-h":
            Console.WriteLine("usage: witness-semantic [--ref-packs DIR] [--version]");
            Console.WriteLine("Reads witness.semantic/1 requests from stdin. See docs/PROTOCOL.md.");
            return 0;
        default:
            Console.Error.WriteLine($"unknown argument: {args[i]}");
            return 2;
    }
}

var server = new Server(refPacks ?? ReferenceResolver.DefaultRefPackDirectory());
using var stdin = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
using var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = false, NewLine = "\n" };

while (!server.ShutdownRequested)
{
    var line = await stdin.ReadLineAsync();
    if (line is null)
    {
        break;
    }
    if (line.Length == 0)
    {
        continue;
    }

    Response response;
    if (Encoding.UTF8.GetByteCount(line) > MaxRequestBytes)
    {
        response = new Response(0, null, new ErrorBody("request_too_large", $"request exceeds {MaxRequestBytes} bytes"));
    }
    else
    {
        Request? request = null;
        try
        {
            request = JsonSerializer.Deserialize<Request>(line, Json.Options)
                ?? throw new ProtocolException("bad_request", "empty request");
            var result = server.Handle(request.Method, request.Params);
            response = new Response(request.Id, result, null);
        }
        catch (ProtocolException ex)
        {
            response = new Response(request?.Id ?? 0, null, new ErrorBody(ex.Code, ex.Message));
        }
        catch (JsonException ex)
        {
            response = new Response(request?.Id ?? 0, null, new ErrorBody("bad_request", ex.Message));
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"witness-semantic: internal error handling {request?.Method}: {ex}");
            response = new Response(request?.Id ?? 0, null, new ErrorBody("internal", ex.GetType().Name + ": " + ex.Message));
        }
    }

    await stdout.WriteLineAsync(JsonSerializer.Serialize(response, Json.Options));
    await stdout.FlushAsync();
}

return 0;
