using Microsoft.EntityFrameworkCore;
using NK.Authentication.Models;
using System.Collections.Generic;

namespace NK.Authentication.Data
{
    public class AppDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    }
}
