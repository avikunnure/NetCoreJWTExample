using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebApplication.Models;

namespace WebApplication.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JwtSettings jwtSettings;

        public AccountController(JwtSettings jwtSettings)
        {
            this.jwtSettings = jwtSettings;
        }

        private IEnumerable<Users> logins=new List<Users>()
        {
            new Users()
            {
                Id = Guid.NewGuid(),
                EmailId = "adminakp@gmail.com",
                UserName ="Admin",
                Password="Admin",
            },
            new Users()
            {
                Id = Guid.NewGuid(),
                EmailId = "adminakp@gmail.com",
                UserName ="User1",
                Password="Admin",
            }
        };

        /// <summary>
        /// Generate an Access token
        /// </summary>
        /// <param name="userLogins"></param>
        /// <returns></returns>
        [HttpPost]
        public IActionResult GetToken(UserLogins userLogins)
        {
            try
            {
                var Token = new UserTokens();
                var Valid = logins.Any(x=>x.UserName.Equals(userLogins.UserName,StringComparison.OrdinalIgnoreCase));
                if (Valid)
                {
                    var user = logins.FirstOrDefault(x => x.UserName.Equals(userLogins.UserName, StringComparison.OrdinalIgnoreCase));
                    Token = JwtHelpers.JwtHelpers.GenTokenkey(new UserTokens()
                    {
                        EmailId = user.EmailId,
                        GuidId = Guid.NewGuid(),
                        UserName = user.UserName,
                        Id = user.Id,

                    }, jwtSettings);
                }
                else
                {
                    return BadRequest($"wrong password");
                }
                return Ok(Token);
            }
            catch (Exception)
            {
                throw;
            }
        }



        /// <summary>
        /// Get List of UserAccounts   
        /// </summary>
        /// <returns>List Of UserAccounts</returns>
        [HttpGet]
        [Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult GetList()
        {
            return Ok(logins);
        }
    }
}
