using Microsoft.EntityFrameworkCore;
using webapp.Models;

namespace webapp.Data;

public class MyDbContext(DbContextOptions<MyDbContext> options) : DbContext(options)
{
    public DbSet<User> Users { get; set; }

    // Override OnConfiguring to configure the MySQL connection
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseMySql("server=localhost;database=main;user=root;password=Localpass.",
            new MySqlServerVersion(new Version(9, 1, 0)));
    }
}