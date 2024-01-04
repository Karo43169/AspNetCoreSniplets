using BookOfGoodPractices.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Graph;
using System.Security.Claims;

namespace BookOfGoodPractices.Middleware
{
    public class CustomSignInMiddleware
    {
        private readonly RequestDelegate _next;
        public CustomSignInMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.User.Identity.IsAuthenticated)
            {
                string userId = context.Request.Headers["x-ms-client-principal-id"].FirstOrDefault();
                string userName = context.Request.Headers["x-ms-client-principal-name"].FirstOrDefault();
                var userManager = context.RequestServices.GetRequiredService<UserManager<AppUser>>();
                if (!string.IsNullOrEmpty(userId))
                {
                    var user = await userManager.FindByIdAsync(userId);
                    if (user == null)
                    {
                        AppUser userIdentity = new()
                        {
                            Id = userId,
                            Email = userName,
                            UserName = userName,
                            FirstName = userName.Substring(0, userName.IndexOf('.')),
                            Surname = userName.Substring(userName.IndexOf('.'), userName.IndexOf('@') - userName.IndexOf('.'))
                        };
                        var result = await userManager.CreateAsync(userIdentity);
                        if (result.Succeeded)
                        {
                            var claim = new List<Claim>
                                {
                                new(ClaimTypes.NameIdentifier, userId),
                                new(ClaimTypes.Name, userName),
                                new(ClaimTypes.Email, userName)
                                };
                            var claimIdentity = new ClaimsIdentity("Custom");
                            claimIdentity.AddClaims(claim);
                            await context.SignInAsync(IdentityConstants.ApplicationScheme, new ClaimsPrincipal(claimIdentity));
                            context.Response.Redirect("/");
                        }
                    }
                    else
                    {
                        IList<string> roles = await userManager.GetRolesAsync(user);
                        ClaimsIdentity claimsIdentity = new("Custom");
                        var claim = new List<Claim>
                        {
                                new(ClaimTypes.NameIdentifier, user.Id),
                                new(ClaimTypes.Name, user.UserName),
                                new(ClaimTypes.Email, user.Email)
                            };
                        foreach (string role in roles)
                        {
                            claim.Add(new(ClaimTypes.Role, role));
                        }
                        claimsIdentity.AddClaims(claim);
                        ClaimsPrincipal claimsPrincipal = new(claimsIdentity);
                        await context.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);
                        context.Response.Redirect("/");
                    }
                }
            }
            else
                await this._next(context);
        }
    }
    public static class CustomSignInMiddlewareExtensions
    {
        public static IApplicationBuilder UseCustomSignIn(this IApplicationBuilder app)
        {
            return app.UseMiddleware<CustomSignInMiddleware>();
        }
    }
}
