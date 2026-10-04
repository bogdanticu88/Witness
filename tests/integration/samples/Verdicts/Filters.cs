using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Verdicts;

public sealed class RejectQuotesAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        if (context.ActionArguments.TryGetValue("q", out var value) && value is string text && text.Contains('\''))
        {
            context.Result = new BadRequestResult();
        }
    }
}

public sealed class TimingAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        context.HttpContext.Items["started"] = DateTime.UtcNow;
    }
}
