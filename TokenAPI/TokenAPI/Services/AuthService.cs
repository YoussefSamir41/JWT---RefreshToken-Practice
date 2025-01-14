using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TokenAPI.Helpers;
using TokenAPI.Models;

namespace TokenAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await userManager.FindByIdAsync(model.UserId);
            if (user is null || !await roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";
            if (await userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";
            var result = await userManager.AddToRoleAsync(user, model.Role);
            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }

        public async Task<AuthModel> Login(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user is null || !await userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }
            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await userManager.GetRolesAsync(user);
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            // authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var activerefreshtoken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authModel.RefreshToken = activerefreshtoken.Token;
                authModel.RefreshTokenExpiration = activerefreshtoken.ExpiresOn;
            }
            else
            {
                var refreshtoken = GenerateRefreshToken();
                authModel.RefreshToken = refreshtoken.Token;
                authModel.RefreshTokenExpiration = refreshtoken.ExpiresOn;
                user.RefreshTokens.Add(refreshtoken);
                await userManager.UpdateAsync(user);
            }




            return authModel;
        }

        public async Task<AuthModel> RefreshTokenAsync(string token)
        {
            var authmodel = new AuthModel();
            var user = await userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(u => u.Token == token));
            if (user == null)
            {

                authmodel.Message = "Invalid Token";
                return authmodel;
            }
            var refreshtoken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshtoken.IsActive)
            {

                authmodel.Message = "Inactive Token";
                return authmodel;
            }
            //Refresh Token is correct and still active 
            refreshtoken.RevokedOn = DateTime.UtcNow;
            var newrefreshtoken = GenerateRefreshToken();
            user.RefreshTokens.Add(newrefreshtoken);
            await userManager.UpdateAsync(user);
            var jwtToken = await CreateJwtToken(user);
            authmodel.IsAuthenticated = true;
            authmodel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authmodel.Email = user.Email;
            authmodel.Username = user.UserName;
            var roles = await userManager.GetRolesAsync(user);
            authmodel.Roles = roles.ToList();
            authmodel.RefreshToken = newrefreshtoken.Token;
            authmodel.RefreshTokenExpiration = newrefreshtoken.ExpiresOn;





            return authmodel;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await userManager.FindByEmailAsync(model.Email) != null)
                return new AuthModel { Message = " Email is Already Regstired:" };
            if (await userManager.FindByNameAsync(model.Username) != null)
                return new AuthModel { Message = " UserName is Already Exist:" };
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                    errors += $"{error.Description},";
                return new AuthModel { Message = errors };
            }
            await userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                //ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName
            };

        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            var user = await userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
                return false;
            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshToken.IsActive)
                return false;
            refreshToken.RevokedOn = DateTime.UtcNow;
            await userManager.UpdateAsync(user);

            return true;
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await userManager.GetClaimsAsync(user);
            var roles = await userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }.Union(userClaims).Union(roleClaims);
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);


            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_jwt.DurationInDays),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;






        }



        private RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(randomNumber);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddDays(10),
                CreatedOn = DateTime.UtcNow
            };
        }
    }
}
