using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;

namespace RLTExample
{
    public class Customer
    {
        public int Id { get; set; }
        public string Name { get; set; }    
    }

    internal class Program
    {
        static void Main(string[] args)
        {

            var builder = WebApplication.CreateBuilder(args);

            var config = builder.Configuration;
            var securityKey = config.GetSection("key").Value;
            

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = "https://localhost:52993",
                        ValidAudience = "https://localhost:52993",
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(securityKey))
                    };
                });            

            builder.Services.AddAuthorization();

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("user", policy => policy.RequireRole("user").RequireClaim("scope", "api"));
                options.AddPolicy("admin", policy => policy.RequireRole("admin").RequireClaim("scope", "api"));
            });

            builder.Services.AddRateLimiter(limiterOptions =>
            {
                limiterOptions.OnRejected = (context, cancellationToken) =>
                {
                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    {
                        context.HttpContext.Response.Headers.RetryAfter =
                            ((int)retryAfter.TotalSeconds).ToString(NumberFormatInfo.InvariantInfo);
                    }

                    context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;                    

                    return new ValueTask();
                };

                limiterOptions.AddPolicy("user_get", context =>
                {
                    var username = "anonymous user";
                    if (context.User.Identity?.IsAuthenticated is true)
                    {
                        username = context.User.Identity.Name;
                    }

                    return RateLimitPartition.GetSlidingWindowLimiter(username,
                        _ => new SlidingWindowRateLimiterOptions
                        {
                            PermitLimit = 10,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 4,
                            Window = TimeSpan.FromSeconds(20),
                            SegmentsPerWindow = 4
                        });
                });

                limiterOptions.AddPolicy("user_post", context =>
                {
                    var username = "anonymous user";
                    if (context.User.Identity?.IsAuthenticated is true)
                    {
                        username = context.User.Identity.Name;
                    }

                    return RateLimitPartition.GetSlidingWindowLimiter(username,
                        _ => new SlidingWindowRateLimiterOptions
                        {
                            PermitLimit = 4,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 2,
                            Window = TimeSpan.FromSeconds(20),
                            SegmentsPerWindow = 4
                        });
                });

                limiterOptions.AddPolicy("admin", context =>
                {
                    return RateLimitPartition.GetNoLimiter("admin");
                });

                limiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                {
                    return RateLimitPartition.GetConcurrencyLimiter("global", _ => new ConcurrencyLimiterOptions
                    {
                        PermitLimit = 20,
                        QueueLimit = 6,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    }); 
                });
            });


            var app = builder.Build();            

            app.UseAuthentication();
            app.UseAuthorization();
            
            app.UseRateLimiter();

            app.MapGet("/", (() => "Hello, World!"));

            app.MapGet("/customer", () =>
            {
                return new List<Customer>
                {
                    new Customer{Id = 1, Name = "John Doe"},
                    new Customer{Id = 2, Name = "Jane Smith"},
                    new Customer{Id = 3, Name = "Bob Johnson"}
                };
            }).RequireAuthorization("user").RequireRateLimiting("user_get");

            app.MapPost("/customer", (Customer newCustomer) =>
            {   
                return Results.Created($"/customer/{newCustomer.Id}", newCustomer); 

            }).RequireAuthorization("user").RequireRateLimiting("user_post");

            app.MapGet("/user", () =>
            {
                return new List<dynamic>
                {
                    new {Id = 1, Name = "Robert James"},
                    new {Id = 2, Name = "Emily Elizabeth"},
                    new {Id = 3, Name = "Michael David"}
                };
            }).RequireAuthorization("admin").RequireRateLimiting("admin");


            app.MapPost("/token", async (HttpContext httpContext) =>
            {
                string username = httpContext.Request.Form["username"];
                string password = httpContext.Request.Form["password"];

                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                {
                    httpContext.Response.StatusCode = 400;
                    await httpContext.Response.WriteAsync("Username or password cannot be empty.");
                    return;
                }

                var claims = new List<Claim>
                {
                    new Claim("scope", "api"),
                    new Claim(ClaimTypes.Name, username),
                };

                if (username.Equals("admin", StringComparison.InvariantCultureIgnoreCase))
                {
                    claims.Add(new Claim(ClaimTypes.Role, "admin"));
                    claims.Add(new Claim(ClaimTypes.Role, "user"));
                }
                else
                {
                    claims.Add(new Claim(ClaimTypes.Role, "user"));
                }


                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var jwtToken = new JwtSecurityToken(
                    issuer: "https://localhost:52993",
                    audience: "https://localhost:52993",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: credentials);

                var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                await httpContext.Response.WriteAsync(token);
            });

            app.Run("https://localhost:52993");
        }
    }
}
