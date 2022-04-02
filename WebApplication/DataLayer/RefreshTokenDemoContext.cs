using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApplication.DataLayer
{
    public class RefreshTokenDemoContext : IdentityDbContext<ApplicationUser>
    {
        public RefreshTokenDemoContext()
        {

        }
        public RefreshTokenDemoContext(DbContextOptions<RefreshTokenDemoContext> options) : base(options)
        {

        }
        public DbSet<ApplicationUser> applicationUsers { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {

            
            modelBuilder.Entity<IdentityUserLogin<Guid>>().HasNoKey();
            modelBuilder.Entity<IdentityUserClaim<Guid>>().HasNoKey();
            modelBuilder.Entity<IdentityUserToken<Guid>>().HasNoKey();
            modelBuilder.Entity<IdentityRoleClaim<Guid>>().HasNoKey();
            base.OnModelCreating(modelBuilder);
        }

    }
}
