using Microsoft.AspNetCore.Identity;

namespace MinhaApiJwt.data
{
  public static class CreateRoles
  {
    public static async Task Execute(IServiceProvider serviceProvider)
    {
      var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

      string[] roleNames = { "Admin", "Manager", "User" };

      foreach (var rolename in roleNames)
      {
        bool roleExists = await roleManager.RoleExistsAsync(rolename);

        if (!roleExists)
        {
          await roleManager.CreateAsync(new IdentityRole(rolename));
        }
      }
    }
  }
}
