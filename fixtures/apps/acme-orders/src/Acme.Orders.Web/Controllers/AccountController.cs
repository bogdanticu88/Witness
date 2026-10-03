using Microsoft.AspNetCore.Mvc;

namespace Acme.Orders.Web.Controllers;

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    [HttpGet("signed-in")]
    public IActionResult SignedIn([FromQuery] string returnUrl)
    {
        return Redirect(returnUrl);
    }

    [HttpGet("continue")]
    public IActionResult Continue([FromQuery] string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return Redirect("/");
    }

    [HttpGet("back")]
    public IActionResult Back([FromQuery] string returnUrl)
    {
        return LocalRedirect(returnUrl);
    }

    [HttpGet("switch")]
    public IActionResult Switch([FromQuery] string returnUrl)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return BadRequest("returnUrl must be local");
        }
        var target = Request.Query["next"].ToString();
        return Redirect(string.IsNullOrEmpty(target) ? returnUrl : target);
    }

    [HttpGet("signed-out")]
    public IActionResult SignedOut([FromQuery] string returnUrl)
    {
        if (!returnUrl.StartsWith('/'))
        {
            return Redirect("/");
        }
        return Redirect(returnUrl);
    }
}
