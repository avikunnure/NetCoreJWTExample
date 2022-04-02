using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication.DataLayer;
using WebApplication.Models;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace WebApplication.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JwtSettings jwtSettings;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RefreshTokenDemoContext refreshTokenDemoContext;

        public AccountController(JwtSettings jwtSettings
            , UserManager<ApplicationUser> userManager
            , RefreshTokenDemoContext refreshTokenDemoContext)
        {
            this.jwtSettings = jwtSettings;
            this.userManager = userManager;
            this.refreshTokenDemoContext = refreshTokenDemoContext;
        }
        [HttpPost]
        public async Task<IActionResult> RegisterUser(Users users)
        {
            try
            {
                var applicationUser = new ApplicationUser()
                {
                    UserName = users.UserName,
                    Email = users.EmailId,
                    FirstName = users.FirstName,
                    LastName = users.LastName,
                    EmailConfirmed = true,
                    TwoFactorEnabled = false,
                    LockoutEnabled = false,

                };
                var result = await userManager.CreateAsync(applicationUser, users.Password);
                if (result.Succeeded)
                {
                    return Ok("User created");
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Generate an Access token
        /// </summary>
        /// <param name="userLogins"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> GetToken(UserLogins userLogins)
        {
            try
            {
                var Token = new UserTokens();
                var user = await userManager.FindByNameAsync(userLogins.UserName);
                if (user == null)
                {
                    return BadRequest("User name is not valid");
                }
                var Valid = await userManager.CheckPasswordAsync(user, userLogins.Password);
                if (Valid)
                {
                    var strToken = Guid.NewGuid().ToString();
                    var validity = DateTime.UtcNow.AddDays(15);
                    Token = JwtHelpers.JwtHelpers.GenTokenkey(new UserTokens()
                    {
                        EmailId = user.Email,
                        GuidId = Guid.NewGuid(),
                        UserName = user.UserName,
                        Id = Guid.Parse(user.Id),
                        RefreshToken = strToken,

                    }, jwtSettings);
                    var tokenupdate = refreshTokenDemoContext.Users.Where(x => x.Id == user.Id).FirstOrDefault();
                    tokenupdate.RefreshToken = strToken;
                    tokenupdate.RefreshTokenValidity = validity;
                    refreshTokenDemoContext.Update(tokenupdate);
                    refreshTokenDemoContext.SaveChanges();
                    Token.RefreshToken = strToken;
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
        /// Generate an Access token
        /// </summary>
        /// <param name="userLogins"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel userLogins)
        {
            try
            {
                var Token = new UserTokens();
                var user = await userManager.FindByNameAsync(userLogins.UserName);
                if (user == null)
                {
                    return BadRequest("User name is not valid");
                }
                var Valid = refreshTokenDemoContext.Users.Where(x=>x.UserName==userLogins.UserName 
                && x.RefreshToken==userLogins.RefreshToken 
                && x.RefreshTokenValidity>DateTime.UtcNow).Count()>0;
                if (Valid)
                {
                    var strToken = Guid.NewGuid().ToString();
                    var validity = DateTime.UtcNow.AddDays(15);
                    Token = JwtHelpers.JwtHelpers.GenTokenkey(new UserTokens()
                    {
                        EmailId = user.Email,
                        GuidId = Guid.NewGuid(),
                        UserName = user.UserName,
                        Id = Guid.Parse(user.Id),
                        RefreshToken = strToken,

                    }, jwtSettings);
                    var tokenupdate = refreshTokenDemoContext.Users.Where(x => x.Id == user.Id).FirstOrDefault();
                    tokenupdate.RefreshToken = strToken;
                    tokenupdate.RefreshTokenValidity = validity;
                    refreshTokenDemoContext.Update(tokenupdate);
                    refreshTokenDemoContext.SaveChanges();
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
            var list = userManager.Users.ToList();
            return Ok(list);
        }
    }
}
