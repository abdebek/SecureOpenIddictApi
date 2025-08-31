using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite("Data Source=openiddict.db");
    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.ClaimsIdentity.UserNameClaimType = Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = Claims.Role;
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetIntrospectionEndpointUris("connect/introspect")
               .SetRevocationEndpointUris("connect/revoke");

        options.AllowPasswordFlow()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "api");
        
        if (builder.Environment.IsDevelopment())
        {
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();
        }
        else
        {
            // In production, load certs from a secure store.
            // options.AddEncryptionCertificate(new X509Certificate2("encryption-certificate.pfx", "password"));
            // options.AddSigningCertificate(new X509Certificate2("signing-certificate.pfx", "password"));
        }


        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableStatusCodePagesIntegration();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("connect/token", async (
    HttpContext context,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) =>
{
    var request = context.GetOpenIddictServerRequest() ??
        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    if (request.IsPasswordGrantType())
    {
        var user = await userManager.FindByNameAsync(request.Username);
        if (user == null)
        {
            return Results.Forbid(
                authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme },
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid username or password."
                }));
        }

        var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            return Results.Forbid(
                authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme },
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid username or password."
                }));
        }

        var principal = await signInManager.CreateUserPrincipalAsync(user);
        principal.SetScopes(request.GetScopes());
        
        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    
    if (request.IsClientCredentialsGrantType())
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.AddClaim(Claims.Subject, request.ClientId ?? throw new InvalidOperationException());
        
        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    if (request.IsRefreshTokenGrantType())
    {
        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = result.Principal;
        
        if (principal == null)
        {
             return Results.Forbid(
                authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme },
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token is no longer valid."
                }));
        }
        
        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    throw new InvalidOperationException("The specified grant type is not supported.");
});

app.MapGet("connect/userinfo", async (HttpContext context, UserManager<ApplicationUser> userManager) =>
{
    var userId = context.User.FindFirstValue(Claims.Subject);
    if (string.IsNullOrEmpty(userId))
    {
        return Results.Challenge(
            authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    var user = await userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return Results.Forbid(
            authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    var claims = new Dictionary<string, object>(StringComparer.Ordinal)
    {
        [Claims.Subject] = await userManager.GetUserIdAsync(user)
    };

    if (context.User.HasScope(Scopes.Email))
    {
        claims[Claims.Email] = await userManager.GetEmailAsync(user) ?? string.Empty;
        claims[Claims.EmailVerified] = await userManager.IsEmailConfirmedAsync(user);
    }

    if (context.User.HasScope(Scopes.Profile))
    {
        claims[Claims.Name] = await userManager.GetUserNameAsync(user) ?? string.Empty;
        claims[Claims.GivenName] = user.FirstName;
        claims[Claims.FamilyName] = user.LastName;
    }
    
    if (context.User.HasScope(Scopes.Roles))
    {
        claims[Claims.Role] = await userManager.GetRolesAsync(user);
    }

    return Results.Ok(claims);
}).RequireAuthorization();

app.MapPost("/register", async (RegisterModel model, UserManager<ApplicationUser> userManager) =>
{
    var user = new ApplicationUser
    {
        UserName = model.Email,
        Email = model.Email,
        FirstName = model.FirstName,
        LastName = model.LastName
    };

    var result = await userManager.CreateAsync(user, model.Password);

    if (!result.Succeeded)
    {
        return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
    }

    return Results.Ok(new { user.Id, user.Email });
});


using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();

    var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    if (await appManager.FindByClientIdAsync("postman") == null)
    {
        await appManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "postman",
            ClientSecret = "postman-secret",
            DisplayName = "Postman Client",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.RefreshToken,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api"
            }
        });
    }

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    if (await userManager.FindByNameAsync("admin@test.com") == null)
    {
        var adminUser = new ApplicationUser
        {
            UserName = "admin@test.com",
            Email = "admin@test.com",
            FirstName = "Admin",
            LastName = "User",
            EmailConfirmed = true
        };
        var adminPassword = "AdminPassword123!";
        var result = await userManager.CreateAsync(adminUser, adminPassword);
        if (result.Succeeded)
        {
            Console.WriteLine($"Default user created. Username: {adminUser.UserName}, Password: {adminPassword}");
        }
    }
}

app.Run();


static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
{
    switch (claim.Type)
    {
        case Claims.Name:
            yield return Destinations.AccessToken;
            if (principal.HasScope(Scopes.Profile))
                yield return Destinations.IdentityToken;
            yield break;
        
        case Claims.Email:
            yield return Destinations.AccessToken;
            if (principal.HasScope(Scopes.Email))
                yield return Destinations.IdentityToken;
            yield break;

        case Claims.Role:
            yield return Destinations.AccessToken;
            if (principal.HasScope(Scopes.Roles))
                yield return Destinations.IdentityToken;
            yield break;

        case "custom_claim":
            yield return Destinations.AccessToken;
            yield return Destinations.IdentityToken;
            yield break;

        default:
            yield return Destinations.AccessToken;
            yield break;
    }
}


public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
}

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }
}

public record RegisterModel(string Email, string Password, string FirstName, string LastName);
