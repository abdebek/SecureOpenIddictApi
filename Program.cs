using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using System.Collections.Immutable;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
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
    options.ClaimsIdentity.EmailClaimType = Claims.Email;
});

// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        // Set the URIs for all endpoints (corrected method names)
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetIntrospectionEndpointUris("connect/introspect")
               .SetRevocationEndpointUris("connect/revoke")
               .SetEndSessionEndpointUris("connect/logout");

        // Enable flows
        options.AllowAuthorizationCodeFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        // Register scopes
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OpenId, "api");

        // Development certificates
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // ASP.NET Core integration (corrected method names)
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .DisableTransportSecurityRequirement(); // For development only
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Add CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
}).AddCookie();
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseStaticFiles();

// Seed the database
await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();

    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    // Create the postman client (fixed property names)
    if (await manager.FindByClientIdAsync("postman") is null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "postman",
            ClientSecret = "postman-secret",
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "Postman Client",
            ClientType = ClientTypes.Confidential, // Corrected from Type to ClientType
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.Revocation,
                Permissions.Endpoints.Introspection,
                Permissions.Endpoints.EndSession, // Corrected from Logout to EndSession
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api"
            },
            RedirectUris = { new Uri("https://localhost:7236/callback.html") }
        });
    }

    // Create the web client (fixed property names)
    if (await manager.FindByClientIdAsync("web-client") is null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "web-client",
            ConsentType = ConsentTypes.Implicit,
            DisplayName = "Web Client",
            ClientType = ClientTypes.Public, // Corrected from Type to ClientType
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession, // Corrected from Logout to EndSession
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api"
            },
            RedirectUris = { 
                new Uri("https://localhost:7236/callback.html"),
                new Uri("http://localhost:5295/callback.html")  // Add HTTP redirect URI
            }
        });
    }

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    if (await userManager.FindByEmailAsync("admin@test.com") is null)
    {
        var user = new ApplicationUser
        {
            UserName = "admin@test.com",
            Email = "admin@test.com",
            FirstName = "Admin",
            LastName = "User",
            EmailConfirmed = true
        };

        await userManager.CreateAsync(user, "AdminPassword123!");
    }
}

// Test Pkce 
app.MapGet("/test/pkce", () => 
{
    var verifier = GenerateRandomString(128);
    var challenge = GenerateCodeChallenge(verifier);
    var state = GenerateRandomString(32);
    
    return Results.Json(new { 
        verifier, 
        challenge, 
        state,
        authUrl = $"https://localhost:7236/connect/authorize?response_type=code&client_id=web-client&redirect_uri=https://localhost:7236/callback.html&scope=openid profile email api&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        curlCommand = $@"
# Step 1: Open the authUrl in browser and get the authorization code
# Step 2: Use this curl command with the code you received:

curl -X POST https://localhost:7236/connect/token \
  -H ""Content-Type: application/x-www-form-urlencoded"" \
  -d ""grant_type=authorization_code"" \
  -d ""client_id=web-client"" \
  -d ""code=PASTE_AUTH_CODE_HERE"" \
  -d ""redirect_uri=https://localhost:7236/callback.html"" \
  -d ""code_verifier={verifier}"""
    });
});

// Authorization endpoint
// Replace your /connect/authorize endpoint with this fixed version:

app.MapGet("/connect/authorize", async (HttpContext context,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictScopeManager scopeManager,
    UserManager<ApplicationUser> userManager) =>
{
    var request = context.GetOpenIddictServerRequest() ??
        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    // If user is not authenticated, redirect to login
    if (!context.User.Identity!.IsAuthenticated)
    {
        var returnUrl = context.Request.GetDisplayUrl();
        return Results.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    // IMPORTANT: GetUserAsync might return null if the claims principal doesn't have the right claims
    // This can happen if the authentication cookie was just set but not properly loaded
    var user = await userManager.GetUserAsync(context.User);
    
    if (user == null)
    {
        // Try to get user by the Name claim (email) as a fallback
        var emailClaim = context.User.FindFirst(ClaimTypes.Name)?.Value 
                      ?? context.User.FindFirst("name")?.Value;
        
        if (!string.IsNullOrEmpty(emailClaim))
        {
            user = await userManager.FindByEmailAsync(emailClaim);
        }
        
        if (user == null)
        {
            // If still null, the authentication state might be stale
            // Force re-authentication
            await context.SignOutAsync();
            var returnUrl = context.Request.GetDisplayUrl();
            return Results.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
        }
    }

    var application = await applicationManager.FindByClientIdAsync(request.ClientId!) ??
        throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
    
    // Create identity with claims
    var identity = new ClaimsIdentity(
        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        nameType: Claims.Name,
        roleType: Claims.Role);

    // Set basic claims first (these are always needed)
    identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
            .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
            .SetClaim(Claims.PreferredUsername, await userManager.GetUserNameAsync(user));

    // Add roles if any
    var roles = await userManager.GetRolesAsync(user);
    if (roles.Any())
    {
        identity.SetClaims(Claims.Role, roles.ToImmutableArray());
    }

    // Set scopes
    identity.SetScopes(request.GetScopes());
    
    // Collect resources
    var resources = new List<string>();
    await foreach (var resource in scopeManager.ListResourcesAsync(identity.GetScopes()))
    {
        resources.Add(resource);
    }
    identity.SetResources(resources);

    // For public clients (like web-client), use simplified flow without storing authorization
    var clientType = await applicationManager.GetClientTypeAsync(application);
    if (clientType == ClientTypes.Public)
    {
        identity.SetDestinations(GetDestinations);
        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // For confidential clients, create and store authorization
    var authorization = await authorizationManager.CreateAsync(
        identity: identity,
        subject: await userManager.GetUserIdAsync(user),
        client: await applicationManager.GetIdAsync(application),
        type: AuthorizationTypes.Permanent,
        scopes: identity.GetScopes());

    identity.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));
    identity.SetDestinations(GetDestinations);

    return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
});

// Token endpoint
app.MapPost("/connect/token", async (HttpContext context,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictScopeManager scopeManager,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) =>
{
    var request = context.GetOpenIddictServerRequest() ??
        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    if (request.IsPasswordGrantType())
    {
        var user = await userManager.FindByNameAsync(request.Username!);
        if (user == null)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
            });
            return Results.Forbid(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme], properties: properties);
        }

        var result = await signInManager.CheckPasswordSignInAsync(user, request.Password!, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
            });
            return Results.Forbid(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme], properties: properties);
        }

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, (await userManager.GetRolesAsync(user)).ToImmutableArray());

        identity.SetScopes(request.GetScopes());
        
        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(identity.GetScopes()))
        {
            resources.Add(resource);
        }
        identity.SetResources(resources);
        identity.SetDestinations(GetDestinations);

        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    else if (request.IsClientCredentialsGrantType())
    {
        var application = await applicationManager.FindByClientIdAsync(request.ClientId!);
        if (application == null)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The client application was not found."
            });
            return Results.Forbid(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]  , properties: properties);
        }

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application))
                .SetClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application));

        identity.SetScopes(request.GetScopes());
        
        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(identity.GetScopes()))
        {
            resources.Add(resource);
        }
        identity.SetResources(resources);
        identity.SetDestinations(GetDestinations);

        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    else if (request.IsAuthorizationCodeGrantType())
    {
        var info = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await userManager.FindByIdAsync(info.Principal!.GetClaim(Claims.Subject)!);
        
        if (user == null)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
            });
            return Results.Forbid(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme], properties: properties);
        }

        var identity = new ClaimsIdentity(info.Principal.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetDestinations(GetDestinations);
        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    else if (request.IsRefreshTokenGrantType())
    {
        var info = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var user = await userManager.FindByIdAsync(info.Principal!.GetClaim(Claims.Subject)!);
        
        if (user == null || !await signInManager.CanSignInAsync(user))
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token is no longer valid."
            });
            return Results.Forbid(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme], properties: properties);
        }

        var identity = new ClaimsIdentity(info.Principal.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetDestinations(GetDestinations);
        return Results.SignIn(new ClaimsPrincipal(identity), properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    var errorProperties = new AuthenticationProperties(new Dictionary<string, string>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified grant type is not supported."
    });
    return Results.Forbid(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme], properties: errorProperties);
});

// UserInfo endpoint
app.MapGet("/connect/userinfo", [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
async (ClaimsPrincipal user, UserManager<ApplicationUser> userManager) =>
{
    var appUser = await userManager.FindByIdAsync(user.GetClaim(Claims.Subject)!);
    if (appUser == null)
    {
        return Results.Challenge(authenticationSchemes: [OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme]);
    }

    var claims = new Dictionary<string, object>(StringComparer.Ordinal)
    {
        [Claims.Subject] = await userManager.GetUserIdAsync(appUser)
    };

    if (user.HasScope(Scopes.Email))
    {
        claims[Claims.Email] = await userManager.GetEmailAsync(appUser) ?? "";
        claims[Claims.EmailVerified] = await userManager.IsEmailConfirmedAsync(appUser);
    }

    if (user.HasScope(Scopes.Profile))
    {
        claims[Claims.Name] = await userManager.GetUserNameAsync(appUser) ?? "";
        claims[Claims.PreferredUsername] = await userManager.GetUserNameAsync(appUser) ?? "";
        claims["first_name"] = appUser.FirstName;
        claims["last_name"] = appUser.LastName;
    }

    if (user.HasScope(Scopes.Roles))
    {
        claims[Claims.Role] = await userManager.GetRolesAsync(appUser);
    }

    return Results.Json(claims);
});

// Registration endpoint
app.MapPost("/register", async (
    UserManager<ApplicationUser> userManager,
    [FromBody] RegisterModel model) =>
{
    if (await userManager.FindByEmailAsync(model.Email) != null)
    {
        return Results.BadRequest(new { error = "User already exists" });
    }

    var user = new ApplicationUser
    {
        UserName = model.Email,
        Email = model.Email,
        FirstName = model.FirstName,
        LastName = model.LastName,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, model.Password);
    if (result.Succeeded)
    {
        return Results.Ok(new { message = "User registered successfully" });
    }

    return Results.BadRequest(new { errors = result.Errors });
});

// Login page
// Replace your /login POST endpoint with this version that uses a 303 redirect:

// Replace both /login endpoints with these versions:

// GET /login - Display login form
app.MapGet("/login", (HttpContext context) =>
{
    var returnUrl = context.Request.Query["returnUrl"].ToString();
    
    // Log for debugging
    app.Logger.LogInformation("GET /login called with returnUrl: {ReturnUrl}", returnUrl);
    
    // URL decode the returnUrl for display purposes
    var decodedUrl = string.IsNullOrEmpty(returnUrl) ? "/" : System.Net.WebUtility.UrlDecode(returnUrl);
    
    return Results.Content($@"
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }}
        .login-form {{ background: #f5f5f5; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input[type='email'], input[type='password'] {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #45a049; }}
        .error {{ color: red; margin-top: 10px; }}
        h2 {{ text-align: center; margin-bottom: 30px; color: #333; }}
        .debug {{ background: #f0f0f0; padding: 10px; margin-top: 20px; font-size: 0.9em; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class='login-form'>
        <h2>Login</h2>
        <form method='post' action='/login'>
            <input type='hidden' name='returnUrl' value='{System.Net.WebUtility.HtmlEncode(returnUrl)}' />
            <div class='form-group'>
                <label for='email'>Email:</label>
                <input type='email' id='email' name='email' value='admin@test.com' required />
            </div>
            <div class='form-group'>
                <label for='password'>Password:</label>
                <input type='password' id='password' name='password' value='AdminPassword123!' required />
            </div>
            <button type='submit'>Login</button>
        </form>
        <div class='debug'>
            <small>Debug: Return URL = {System.Net.WebUtility.HtmlEncode(decodedUrl)}</small>
        </div>
    </div>
</body>
</html>", "text/html");
});

// POST /login - Process login
app.MapPost("/login", async (
    HttpContext context,
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager) =>
{
    // Read form data
    var form = await context.Request.ReadFormAsync();
    var email = form["email"].ToString();
    var password = form["password"].ToString();
    var returnUrl = form["returnUrl"].ToString();
    
    // Log for debugging
    app.Logger.LogInformation("POST /login called - Email: {Email}, HasReturnUrl: {HasReturn}", 
        email, !string.IsNullOrEmpty(returnUrl));

    // Validate input
    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
    {
        app.Logger.LogWarning("Login failed: Missing email or password");
        return Results.BadRequest("Email and password are required");
    }

    var user = await userManager.FindByEmailAsync(email);
    if (user == null)
    {
        app.Logger.LogWarning("Login failed: User not found for email {Email}", email);
        // Don't reveal that the user doesn't exist
        return ShowLoginError(email, returnUrl);
    }

    var result = await signInManager.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: false);
    
    if (result.Succeeded)
    {
        app.Logger.LogInformation("Login successful for {Email}, redirecting to: {ReturnUrl}", 
            email, string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl);
        
        // Decode the return URL
        var decodedReturnUrl = string.IsNullOrEmpty(returnUrl) ? "/" : System.Net.WebUtility.UrlDecode(returnUrl);
        
        // Method 1: Try using a meta refresh as a workaround
        return Results.Content($@"
<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv='refresh' content='0;url={System.Net.WebUtility.HtmlEncode(decodedReturnUrl)}'>
</head>
<body>
    <p>Login successful. Redirecting...</p>
    <p>If you are not redirected, <a href='{System.Net.WebUtility.HtmlEncode(decodedReturnUrl)}'>click here</a>.</p>
</body>
</html>", "text/html");
        
        // Method 2: Alternative - use JavaScript redirect (comment out Method 1 and uncomment this to try)
        /*
        return Results.Content($@"
<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <script>
        window.location.href = '{decodedReturnUrl.Replace("'", "\\'").Replace("\n", "").Replace("\r", "")}';
    </script>
</head>
<body>
    <p>Login successful. Redirecting...</p>
    <p>If you are not redirected, <a href='{System.Net.WebUtility.HtmlEncode(decodedReturnUrl)}'>click here</a>.</p>
</body>
</html>", "text/html");
        */
    }
    
    app.Logger.LogWarning("Login failed for {Email}: {Reason}", 
        email, result.IsLockedOut ? "Locked out" : "Invalid password");
    
    return ShowLoginError(email, returnUrl);
    
    // Helper function to show login error
    IResult ShowLoginError(string attemptedEmail, string returnUrlParam)
    {
        return Results.Content($@"
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }}
        .login-form {{ background: #f5f5f5; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input[type='email'], input[type='password'] {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #45a049; }}
        .error {{ color: red; margin-top: 10px; }}
        h2 {{ text-align: center; margin-bottom: 30px; color: #333; }}
    </style>
</head>
<body>
    <div class='login-form'>
        <h2>Login</h2>
        <div class='error'>Invalid email or password.</div>
        <form method='post' action='/login'>
            <input type='hidden' name='returnUrl' value='{System.Net.WebUtility.HtmlEncode(returnUrlParam)}' />
            <div class='form-group'>
                <label for='email'>Email:</label>
                <input type='email' id='email' name='email' value='{System.Net.WebUtility.HtmlEncode(attemptedEmail)}' required />
            </div>
            <div class='form-group'>
                <label for='password'>Password:</label>
                <input type='password' id='password' name='password' value='' required />
            </div>
            <button type='submit'>Login</button>
        </form>
    </div>
</body>
</html>", "text/html");
    }
});

// Default route - serves the client app
app.MapGet("/", () => Results.Content(@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>OpenIddict Demo Client</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .container {
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 90%;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 2rem;
        }
        
        .user-info {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 1.5rem;
            border-left: 4px solid #28a745;
        }
        
        .user-info h3 {
            color: #495057;
            margin-bottom: 1rem;
        }
        
        .info-item {
            margin-bottom: 0.5rem;
            display: flex;
            justify-content: space-between;
        }
        
        .label {
            font-weight: bold;
            color: #6c757d;
        }
        
        .value {
            color: #495057;
        }
        
        .buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        button {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 120px;
        }
        
        .btn-primary {
            background: #007bff;
            color: white;
        }
        
        .btn-primary:hover {
            background: #0056b3;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,123,255,0.4);
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #1e7e34;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(40,167,69,0.4);
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(220,53,69,0.4);
        }
        
        .auth-info {
            margin-top: 1rem;
            padding: 1rem;
            background: #e9ecef;
            border-radius: 8px;
            font-size: 0.9rem;
        }
        
        .hidden {
            display: none;
        }
        
        .status-message {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
        }
        
        .status-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .status-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class=""container"">
        <h1>OpenIddict Demo Client</h1>
        
        <div id=""status-message"" class=""hidden""></div>
        
        <div id=""logged-out"" class=""auth-section"">
            <div class=""auth-info"">
                <p>Welcome to the OpenIddict Demo! This client demonstrates the Authorization Code flow with PKCE.</p>
                <p><strong>Demo credentials:</strong></p>
                <p>Email: admin@test.com</p>
                <p>Password: AdminPassword123!</p>
            </div>
            <div class=""buttons"">
                <button class=""btn-primary"" onclick=""login()"">Login with OpenIddict</button>
            </div>
        </div>
        
        <div id=""logged-in"" class=""auth-section hidden"">
            <div class=""user-info"">
                <h3>User Information</h3>
                <div class=""info-item"">
                    <span class=""label"">Name:</span>
                    <span class=""value"" id=""user-name"">-</span>
                </div>
                <div class=""info-item"">
                    <span class=""label"">Email:</span>
                    <span class=""value"" id=""user-email"">-</span>
                </div>
                <div class=""info-item"">
                    <span class=""label"">Subject:</span>
                    <span class=""value"" id=""user-subject"">-</span>
                </div>
                <div class=""info-item"">
                    <span class=""label"">First Name:</span>
                    <span class=""value"" id=""user-firstname"">-</span>
                </div>
                <div class=""info-item"">
                    <span class=""label"">Last Name:</span>
                    <span class=""value"" id=""user-lastname"">-</span>
                </div>
            </div>
            
            <div class=""buttons"">
                <button class=""btn-success"" onclick=""getUserInfo()"">Refresh User Info</button>
                <button class=""btn-danger"" onclick=""logout()"">Logout</button>
            </div>
        </div>
    </div>

    <script>
        class OpenIddictClient {
            constructor() {
                this.clientId = 'web-client';
                this.redirectUri = window.location.origin + '/callback.html';
                this.authorizationEndpoint = '/connect/authorize';
                this.tokenEndpoint = '/connect/token';
                this.userinfoEndpoint = '/connect/userinfo';
                this.scope = 'openid profile email api';
                
                this.init();
            }
            
            init() {
                const token = localStorage.getItem('access_token');
                if (token) {
                    this.showLoggedIn();
                    this.getUserInfo();
                } else {
                    this.showLoggedOut();
                }
            }
            
            async generatePKCE() {
                const codeVerifier = this.generateRandomString(128);
                const encoder = new TextEncoder();
                const data = encoder.encode(codeVerifier);
                const digest = await crypto.subtle.digest('SHA-256', data);
                const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                    
                return { codeVerifier, codeChallenge };
            }
            
            generateRandomString(length) {
                const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
                let result = '';
                for (let i = 0; i < length; i++) {
                    result += charset.charAt(Math.floor(Math.random() * charset.length));
                }
                return result;
            }
            
            async login() {
                try {
                    const { codeVerifier, codeChallenge } = await this.generatePKCE();
                    const state = this.generateRandomString(32);
                    
                    localStorage.setItem('code_verifier', codeVerifier);
                    localStorage.setItem('oauth_state', state);
                    
                    const params = new URLSearchParams({
                        response_type: 'code',
                        client_id: this.clientId,
                        redirect_uri: this.redirectUri,
                        scope: this.scope,
                        state: state,
                        code_challenge: codeChallenge,
                        code_challenge_method: 'S256'
                    });
                    
                    window.location.href = `${this.authorizationEndpoint}?${params.toString()}`;
                } catch (error) {
                    this.showError('Login failed: ' + error.message);
                }
            }
            
            async getUserInfo() {
                const token = localStorage.getItem('access_token');
                if (!token) {
                    this.showLoggedOut();
                    return;
                }
                
                try {
                    const response = await fetch(this.userinfoEndpoint, {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }
                    
                    const userInfo = await response.json();
                    this.displayUserInfo(userInfo);
                    this.showSuccess('User information loaded successfully!');
                } catch (error) {
                    this.showError('Failed to get user info: ' + error.message);
                    if (error.message.includes('401')) {
                        this.logout();
                    }
                }
            }
            
            displayUserInfo(userInfo) {
                document.getElementById('user-name').textContent = userInfo.name || '-';
                document.getElementById('user-email').textContent = userInfo.email || '-';
                document.getElementById('user-subject').textContent = userInfo.sub || '-';
                document.getElementById('user-firstname').textContent = userInfo.first_name || '-';
                document.getElementById('user-lastname').textContent = userInfo.last_name || '-';
            }
            
            logout() {
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                this.showLoggedOut();
                this.showSuccess('Logged out successfully!');
            }
            
            showLoggedIn() {
                document.getElementById('logged-out').classList.add('hidden');
                document.getElementById('logged-in').classList.remove('hidden');
            }
            
            showLoggedOut() {
                document.getElementById('logged-in').classList.add('hidden');
                document.getElementById('logged-out').classList.remove('hidden');
            }
            
            showError(message) {
                const statusDiv = document.getElementById('status-message');
                statusDiv.textContent = message;
                statusDiv.className = 'status-message status-error';
                statusDiv.classList.remove('hidden');
                setTimeout(() => statusDiv.classList.add('hidden'), 5000);
            }
            
            showSuccess(message) {
                const statusDiv = document.getElementById('status-message');
                statusDiv.textContent = message;
                statusDiv.className = 'status-message status-success';
                statusDiv.classList.remove('hidden');
                setTimeout(() => statusDiv.classList.add('hidden'), 3000);
            }
        }
        
        const client = new OpenIddictClient();
        
        function login() {
            client.login();
        }
        
        function getUserInfo() {
            client.getUserInfo();
        }
        
        function logout() {
            client.logout();
        }
    </script>
</body>
</html>", "text/html"));

// Callback page
app.MapGet("/callback.html", () => Results.Content(@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Processing Login...</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        
        .container {
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        h2 {
            color: #333;
            margin-bottom: 1rem;
        }
        
        p {
            color: #666;
            margin-bottom: 2rem;
        }
        
        .error {
            color: #dc3545;
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class=""container"">
        <h2>Processing Login</h2>
        <div class=""spinner""></div>
        <p>Please wait while we complete your login...</p>
        <div id=""error-message"" class=""error"" style=""display: none;""></div>
    </div>

    <script>
        (async function() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const code = urlParams.get('code');
                const state = urlParams.get('state');
                const error = urlParams.get('error');
                
                if (error) {
                    throw new Error(urlParams.get('error_description') || error);
                }
                
                if (!code) {
                    throw new Error('No authorization code received');
                }
                
                const storedState = localStorage.getItem('oauth_state');
                if (state !== storedState) {
                    throw new Error('Invalid state parameter');
                }
                
                const codeVerifier = localStorage.getItem('code_verifier');
                if (!codeVerifier) {
                    throw new Error('Code verifier not found');
                }
                
                const params = new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: 'web-client',
                    code: code,
                    redirect_uri: window.location.origin + '/callback.html',
                    code_verifier: codeVerifier
                });
                
                const response = await fetch('/connect/token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: params.toString()
                });
                
                if (!response.ok) {
                    const error = await response.text();
                    throw new Error(`Token exchange failed: ${error}`);
                }
                
                const tokenData = await response.json();
                
                localStorage.setItem('access_token', tokenData.access_token);
                if (tokenData.refresh_token) {
                    localStorage.setItem('refresh_token', tokenData.refresh_token);
                }
                
                localStorage.removeItem('code_verifier');
                localStorage.removeItem('oauth_state');
                
                window.location.href = '/';
                
            } catch (error) {
                document.getElementById('error-message').textContent = 'Error: ' + error.message;
                document.getElementById('error-message').style.display = 'block';
                document.querySelector('.spinner').style.display = 'none';
                document.querySelector('p').textContent = 'Login failed. Redirecting...';
                
                setTimeout(() => {
                    window.location.href = '/';
                }, 3000);
            }
        })();
    </script>
</body>
</html>", "text/html"));

app.Run();

// Helper method for claim destinations
static IEnumerable<string> GetDestinations(Claim claim)
{
    switch (claim.Type)
    {
        case Claims.Name:
            yield return Destinations.AccessToken;
            if (claim.Subject.HasScope(Scopes.Profile))
                yield return Destinations.IdentityToken;
            yield break;

        case Claims.Email:
            yield return Destinations.AccessToken;
            if (claim.Subject.HasScope(Scopes.Email))
                yield return Destinations.IdentityToken;
            yield break;

        case Claims.Role:
            yield return Destinations.AccessToken;
            if (claim.Subject.HasScope(Scopes.Roles))
                yield return Destinations.IdentityToken;
            yield break;

        case "AspNet.Identity.SecurityStamp":
            yield break;

        default:
            yield return Destinations.AccessToken;
            yield break;
    }
}

static string GenerateRandomString(int length)
{
    const string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    var random = new Random();
    var result = new char[length];
    
    for (int i = 0; i < length; i++)
    {
        result[i] = charset[random.Next(charset.Length)];
    }
    
    return new string(result);
}

// Helper method to generate code challenge from verifier
static string GenerateCodeChallenge(string codeVerifier)
{
    using var sha256 = System.Security.Cryptography.SHA256.Create();
    var challengeBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));
    
    // Convert to base64url encoding
    var challenge = Convert.ToBase64String(challengeBytes)
        .Replace("+", "-")
        .Replace("/", "_")
        .Replace("=", "");
    
    return challenge;
}

// Application User model
public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
}

// Database context
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }
}

// Registration model
public record RegisterModel(
    string Email,
    string Password,
    string FirstName,
    string LastName
);