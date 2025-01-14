using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TokenAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class SecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok("Hello from secured controller");
        }
    }
}
