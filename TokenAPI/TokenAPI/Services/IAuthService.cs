using TokenAPI.Models;

namespace TokenAPI.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> Login(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
        Task<bool> RevokeTokenAsync(string token);
        Task<AuthModel> RefreshTokenAsync(string token);
    }
}
