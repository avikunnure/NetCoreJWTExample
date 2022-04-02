using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using WebApplication.DataLayer;
using Microsoft.AspNetCore.Identity;

namespace WebApplication.Extensions
{
    public static class IdentityServicesExtensions
    {
        public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<RefreshTokenDemoContext>(options =>
                options.UseNpgsql(configuration.GetConnectionString("RefreshTokenDB")));

            services.AddIdentityCore<ApplicationUser>()
                .AddDefaultTokenProviders()
                .AddEntityFrameworkStores<RefreshTokenDemoContext>();
            return services;
        }
    }
}
