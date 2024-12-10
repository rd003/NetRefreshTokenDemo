using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetRefreshTokenDemo.Api.Constants;

namespace NetRefreshTokenDemo.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class PeopleController : ControllerBase
{

    [HttpGet]
    public IActionResult Get()
    {
        return Ok();
    }

    [HttpPost]
    [Authorize(Roles = Roles.Admin)]
    public IActionResult Post()
    {
        return Ok();
    }
}