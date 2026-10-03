namespace Acme.Orders.Web.Services;

// Removes the nightly export file named in configuration once it is older
// than a day. The path is operator configuration, never request input.
public sealed class ExportCleanupService : BackgroundService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<ExportCleanupService> _logger;

    public ExportCleanupService(IConfiguration configuration, ILogger<ExportCleanupService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var exportPath = _configuration["Export:Path"];
        while (!stoppingToken.IsCancellationRequested && !string.IsNullOrEmpty(exportPath))
        {
            if (File.Exists(exportPath) && File.GetLastWriteTimeUtc(exportPath) < DateTime.UtcNow.AddDays(-1))
            {
                File.Delete(exportPath);
                _logger.LogInformation("Removed stale export");
            }
            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}
