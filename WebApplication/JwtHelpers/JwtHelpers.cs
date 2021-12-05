using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WebApplication.Models;

namespace WebApplication.JwtHelpers
{
    public static class JwtHelpers
    {

        public static IEnumerable<Claim> GetClaims(this UserTokens userAccounts, Guid Id)
        {
            IEnumerable<Claim> claims = new Claim[]
                    {
                new Claim("Id",userAccounts.Id.ToString()),
                new Claim(ClaimTypes.Name, userAccounts.UserName),
                new Claim(ClaimTypes.Email, userAccounts.EmailId),
                new Claim(ClaimTypes.NameIdentifier,Id.ToString()),
                new Claim(ClaimTypes.Expiration,DateTime.UtcNow.AddDays(1).ToString("MMM ddd dd yyyy HH:mm:ss tt") )
                    };
            return claims;
        }
        public static IEnumerable<Claim> GetClaims(this UserTokens userAccounts, out Guid Id)
        {
            Id = Guid.NewGuid();
            return GetClaims(userAccounts, Id);
        }
        public static UserTokens GenTokenkey(UserTokens model, JwtSettings jwtSettings)
        {
            try
            {
                var UserToken = new UserTokens();
                if (model == null) throw new ArgumentException(nameof(model));

                // Get secret key
                var key = System.Text.Encoding.ASCII.GetBytes(jwtSettings.IssuerSigningKey);
                Guid Id = Guid.Empty;
                DateTime expireTime = DateTime.UtcNow.AddDays(1);
                UserToken.Validaty = expireTime.TimeOfDay;
                var JWToken = new JwtSecurityToken(
                    issuer: jwtSettings.ValidIssuer,
                    audience: jwtSettings.ValidAudience,
                    claims: GetClaims(model, out Id),
                    notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                    expires: new DateTimeOffset(expireTime).DateTime,
                    signingCredentials: new SigningCredentials
                    (new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
                );
                UserToken.Token = new JwtSecurityTokenHandler().WriteToken(JWToken);
                var idRefreshToken = Guid.NewGuid();
                var JWRefreshToken = new JwtSecurityToken(
                   issuer: jwtSettings.ValidIssuer,
                   audience: jwtSettings.ValidAudience,
                   claims: GetClaims(model, idRefreshToken),
                   notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                   expires: new DateTimeOffset(DateTime.Now.AddMonths(12)).DateTime,
                   signingCredentials: new SigningCredentials
                   (new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
                );

                UserToken.RefreshToken =  new JwtSecurityTokenHandler().WriteToken(JWRefreshToken);
                UserToken.UserName = model.UserName;
                UserToken.Id = model.Id;
                UserToken.GuidId = Id;
                return UserToken;
            }
            catch (Exception)
            {
                throw;
            }
        }


        public static UserTokens? GetTokenFromRefreshToken(string token, JwtSettings jwtSettings)
        {
            try
            {
                var strid = "_+_+_";
                var strinsg = token.Split(strid);
                if (string.IsNullOrEmpty(token)) throw new ArgumentException(nameof(token));
                var key = System.Text.Encoding.ASCII.GetBytes(jwtSettings.IssuerSigningKey);
                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = jwtSettings.ValidateIssuer,
                    ValidIssuer = jwtSettings.ValidIssuer,
                    ValidateAudience = jwtSettings.ValidateAudience,
                    ValidAudience = jwtSettings.ValidAudience,
                    RequireExpirationTime = jwtSettings.RequireExpirationTime,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromDays(1)
                }, out SecurityToken validatedSecurityToken);

                var jwtExtractedToken = (JwtSecurityToken)validatedSecurityToken;
                var adminId = Guid.Parse(jwtExtractedToken.Claims.First(x => x.Type.Contains("Id")).Value);
                string userName = jwtExtractedToken.Claims.First(x => x.Type.Contains(ClaimTypes.Name)).Value;

                string emailaddress = jwtExtractedToken.Claims.First(x => x.Type.Contains(ClaimTypes.Email)).Value;
                Guid guidId = Guid.Parse(jwtExtractedToken.Claims.First(x => x.Type.Contains(ClaimTypes.NameIdentifier)).Value);
                DateTime expiredTime = (jwtExtractedToken.Claims.First(x => x.Type.Contains(ClaimTypes.Expiration)).Value).ParseDateTimeExact();

                return new UserTokens()
                {
                    Id = adminId,
                    UserName = userName,

                    EmailId = emailaddress,

                    Token = token,
                    GuidId = guidId,
                    ExpiredTime = expiredTime,

                };
            }
            catch (Exception)
            {
                return null;
            }
        }
        public static DateTime ParseDateTimeExact(this object obj)
        {
            if (obj == null || string.IsNullOrEmpty(obj.ToString()))
                return DateTime.Now;

            DateTime result;
            if (!DateTime.TryParseExact(obj.ToString(), "MMM ddd dd yyyy HH:mm:ss tt", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out result))
                return DateTime.Now;

            return result;
        }
    }
}
